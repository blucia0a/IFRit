#define DEBUG_TYPE "insert-drd-calls"

#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/Statistic.h>
#include <llvm/DebugInfo.h>
#include <llvm/Analysis/Dominators.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Assembly/Writer.h>
#include <llvm/IR/Constants.h>
#include <llvm/InitializePasses.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>
#include <llvm/Support/CFG.h>
#include <llvm/Support/CallSite.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/PassManager.h>

#include <iostream>
#include <list>
#include <map>

#define INSERT_DECL_IFRS
//#undef INSERT_DECL_IFRS

//#define INSERT_CHECK_IFRS

namespace llvm{
  ModulePass *createInsertDRDCallsPass();
}

namespace {

    static void registerIFRIT(const llvm::PassManagerBuilder &, llvm::PassManagerBase &PM) {
        PM.add(llvm::createInsertDRDCallsPass());
    }

    // Run pass after dominator tree is created.
    static llvm::RegisterStandardPasses 
        RegisterIFRIT(llvm::PassManagerBuilder::EP_EnabledOnOptLevel0, registerIFRIT);
}

using namespace llvm;

namespace {

  class InsertDRDCalls : public ModulePass {
  public:
    static char ID;
    InsertDRDCalls() : ModulePass(ID), counter(1) { }
    ~InsertDRDCalls() { }
    virtual void getAnalysisUsage(AnalysisUsage &AU) const;
    bool runOnModule(Module &M);
    bool doInitialization(Module &M);
    const char *getPassName () const;
  private:
    typedef enum { MayWriteIFR = 0, MustWriteIFR = 1 } IFRType;
    typedef std::set<Instruction *> InstructionSet;
    typedef std::pair<IFRType, InstructionSet> IFRInfo;
    typedef std::map<Value *, IFRInfo> IFRs;

    std::map<CallInst *, IFRs> ReleaseIFRs;
    std::map<CallInst *, IFRs> CallIFRs;
    std::map<BasicBlock *, std::map<BasicBlock *, IFRs> > BasicBlockIFRs;
#ifdef INSERT_DECL_IFRS
    IFRs DeclIFRs;
#endif

    std::map<CallInst *, std::map<Value *, IFRType> > AcquireCallForwardsIFRs;
    std::map<BasicBlock *, IFRs> BasicBlockBackwardsIFRs;
    std::map<BasicBlock *, std::map<Value *, IFRType> > BasicBlockForwardsIFRs;

    void doBackwardsAnalysis(Function &F);
    IFRs getEntryIFRs(BasicBlock &);
    IFRs *backwardsTranslatePHI(IFRs &, BasicBlock &, BasicBlock &);
    IFRs joinIFRs(std::list<IFRs *> &);
    bool isAcquire(Instruction &);
    bool isRelease(Instruction &);
    bool isNone(Instruction &);
    void saveBasicBlockIFRs(Module *M,
			    std::map<BasicBlock *, IFRs> &,
			    std::map<BasicBlock *, IFRs> &);
    void clearUndeclaredIFRs();
    void doForwardsAnalysis(Function &F);
    std::map<Value *, IFRType> getForwardsEntryIFRs(BasicBlock &);
    std::map<Value *, IFRType> *forwardsTranslatePHI
    (std::map<Value *, IFRType> &ifrs, BasicBlock &pred, BasicBlock &succ);
    std::map<Value *, IFRType> joinForwardsIFRs(std::list<std::map<Value *,
						IFRType> *> &);
    void findBasicBlockIFRs(Function &F);
    void pruneAcquireIFRs();

    Function *createBeginIFRFunction(Module &M);
    Function *createBeginReadIFRFunction(Module &M);
    Function *createBeginWriteIFRFunction(Module &M);
    Function *createEndIFRsFunction(Module &M);

    enum IFRPlacement {IFRCallPlacement, IFRBBPlacement, IFRDeclPlacement,
		       IFRReleasePlacement };

    void PrintIFRInfo(unsigned long id,
		      Instruction *,
		      std::vector<std::pair<Value *, IFRInfo *> > *,
		      bool, bool, IFRPlacement);

    /// The analysis tracks function calls where it's possible to
    /// start IFRs for one or more variables. E.g., if the IFR for a
    /// load extends to just after a call to pthread_mutex_lock, we
    /// will add a call to ___begin_ifrs right after that call.
    void insertBeginIFRCalls(Module &M);

    void insertCallIFRs(Module &, Function *);

#ifdef INSERT_DECL_IFRS
    void insertDeclIFRs(Module &, Function *, Function *);
#endif

    void insertBasicBlockIFRs(Module &, Function *);

    void instrumentReleaseCalls(Module &M, std::string Name);

    void instrumentReleaseAcquireCalls(Module &M, std::string Name);

    void instrumentOtherCalls(Module &M, std::string Name);

    void insertEndIFRCalls(Module &M, std::string Name);

    FunctionType *constructNewFunctionType(Function *F, bool UseIFRs);

    void replaceAllCalls(Module &M, Function *Old, Function *New, bool UseIFRs);

    void trivialInstrumentation(Module &M,
				Function *BeginReadIFR,
				Function *BeginWriteIFR);

#ifdef INSERT_CHECK_IFRS
    Function *createCheckIFRFunction(Module &M);
    void insertCheckIFRs(Module &M);
#endif

    raw_fd_ostream *OutputFile;

    unsigned long counter;
  };
} // end anonymous namespace

char InsertDRDCalls::ID = 0;

ModulePass *llvm::createInsertDRDCallsPass() {
  return new InsertDRDCalls();
}
    
bool InsertDRDCalls::doInitialization(Module &M){
  outs() << "Initializing IFRit Pass\n";
  return false;
}

const char *InsertDRDCalls::getPassName () const {
    return "Insert IFRit Data-race Detection Calls Transformation";
}

void InsertDRDCalls::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.addRequired<DominatorTree>();
}

bool InsertDRDCalls::runOnModule(Module &M) {
  outs() << "Running InsertDRDCalls on module " << M.getModuleIdentifier() << "\n";

  // Do a backwards (ABNA) analysis to find IFRs that start at calls
  // and at basic block entries.
  for (Module::iterator it = M.begin(); it != M.end(); it++) {
    Function &F = *it;
    if (F.size() == 0) continue;
    doBackwardsAnalysis(F);
  }

  // Go through CallIFRs, BasicBlockBackwardsIFRs, and ReleaseIFRs,
  // removing IFRs for variables that have not been declared as of the
  // beginning of the IFR.
  clearUndeclaredIFRs();

  for (Module::iterator it = M.begin(); it != M.end(); it++) {
    Function &F = *it;
    if (F.size() == 0) continue;

    // Do a forwards analysis to find IFRs that dominate other IFRs,
    // reducing the number of ___begin_ifr calls we need.
    doForwardsAnalysis(F);

    // Use the results of the forwards and backwards analyses to find
    // IFRs that start at basic block boundaries.
    findBasicBlockIFRs(F);
  }

  // Remove duplicate IFRs from acquire calls.
  pruneAcquireIFRs();

  std::string ErrorInfo;
  OutputFile = new raw_fd_ostream("ifrs.txt", ErrorInfo,
				  sys::fs::F_Append);
  if (!ErrorInfo.empty()) {
    errs() << "Error opening 'ifrs.txt': " << ErrorInfo << '\n';
    exit(1);
  }

  insertBeginIFRCalls(M);

  // These functions have release semantics, so it is safe to
  // propagate IFRs through them as long as the IFR's variable is
  // known to be accessed after the call.
  instrumentReleaseCalls(M, "pthread_mutex_unlock");
  instrumentReleaseCalls(M, "pthread_create");
  instrumentReleaseCalls(M, "free");
  instrumentReleaseCalls(M, "pthread_rwlock_unlock");
  instrumentReleaseCalls(M, "pthread_spin_unlock");

  // These functions perform synchronization but do not have simple
  // release or acq/rel semantics. Therefore we must kill all IFRs
  // here because the IFRs' variables could be safely modified by
  // another thread during the call.
  instrumentReleaseAcquireCalls(M, "pthread_cond_wait");
  instrumentReleaseAcquireCalls(M, "pthread_cond_timedwait");
  instrumentReleaseAcquireCalls(M, "pthread_barrier_wait");
  instrumentReleaseAcquireCalls(M, "realloc");

  insertEndIFRCalls(M, "_ZdaPv");
  insertEndIFRCalls(M, "_ZdlPv");
  insertEndIFRCalls(M, "__cxa_guard_release");

//   instrumentOtherCalls(M, "malloc");
//   instrumentOtherCalls(M, "calloc");
//   instrumentOtherCalls(M, "realloc");
//   instrumentOtherCalls(M, "free");
//  instrumentOtherCalls(M, "memcpy");

#ifdef INSERT_CHECK_IFRS
  insertCheckIFRs(M);
#endif

  delete(OutputFile);

  return true;
}

void InsertDRDCalls::doBackwardsAnalysis(Function &F) {

  // Construct a worklist of basic blocks to process
  std::set<BasicBlock *> Worklist;

  // Add all exit blocks to worklist
  for (Function::iterator fi = F.begin(); fi != F.end(); fi++) {
    if (fi->getTerminator()->getNumSuccessors() == 0) {
      Worklist.insert(fi);
    }
  }

  // Pull a block off the worklist and process it
  while (!Worklist.empty()) {
    std::set<BasicBlock *>::iterator si = Worklist.begin();
    BasicBlock &B = **si;
    Worklist.erase(si);


    // Save the old exit values for this block, so we can track
    // whether we need to process its successors again. If this is
    // the first pass over this block, we will always process its
    // successors.
    std::map<BasicBlock *, IFRs>::iterator i = BasicBlockBackwardsIFRs.find(&B);
    IFRs ABNAOld;
    bool FirstPass = false;
    if (i == BasicBlockBackwardsIFRs.end()) {
      // This is the first time this block has been processed, so we
      // will also need to process its successors
      FirstPass = true;
    } else {
      // This block has been processed before - save the old exit
      // information so we can compare when we've finished analyzing
      // it
      ABNAOld = i->second;
    }

    // Determine RAR and RB at entry to the basic block by merging
    // it with any entry info
    IFRs ABNA = getEntryIFRs(B);

    // Iterate through the instructions in this basic block,
    // modifying the RAR/RB/RF bits as appropriate
    for (BasicBlock::iterator bi = B.end(); bi != B.begin(); ) {
      bi--;

      // Accesses since last lock: for a load/store instruction, add
      // the pointer operand to the current set. After a release call
      // or an unknown function call, empty. Propagates through
      // acquire calls and all other operations.
      if (LoadInst *I = dyn_cast<LoadInst>(bi)) {
	Value *V = I->getPointerOperand();
	if (ABNA[V].first == MayWriteIFR ||
	    ABNA[V].first == MustWriteIFR) {
	} else {
	  ABNA[V].first = MayWriteIFR;
	}
	ABNA[V].second.insert(I);
      } else if (StoreInst *I = dyn_cast<StoreInst>(bi)) {
	Value *V = I->getPointerOperand();
	ABNA[V].first = MustWriteIFR;
	ABNA[V].second.insert(I);
      } else if (CallInst *I = dyn_cast<CallInst>(bi)) {
	if (isRelease(*I)) {
	  ReleaseIFRs[I] = ABNA;
	} else if (isNone(*I)) {
	  // do nothing
	} else {
	  CallIFRs[I] = ABNA;
	  ABNA.clear();
	}
      } else if (dyn_cast<InvokeInst>(bi)) {
	ABNA.clear();
      }
    }

    // Now ABNAIn represents the final value of ABNA for this block -
    // has it been updated by this pass?
    if (FirstPass || ABNA != ABNAOld) {
      BasicBlockBackwardsIFRs[&B] = ABNA;

      // Add predecessors to worklist
      for (pred_iterator pi = pred_begin(&B), pe = pred_end(&B);
	   pi != pe; pi++) {
	BasicBlock *PB = *pi;
	Worklist.insert(PB);
      }
    }
  }
}

InsertDRDCalls::IFRs
InsertDRDCalls::getEntryIFRs
(BasicBlock &B) {
  std::list<IFRs *> IFRsList;
  for (succ_iterator si = succ_begin(&B), se = succ_end(&B);
       si != se; si++) {
    BasicBlock &SB = **si;
    std::map<BasicBlock *, IFRs>::iterator sii =
      BasicBlockBackwardsIFRs.find(&SB);
    if (sii != BasicBlockBackwardsIFRs.end()) {
      IFRs *ifrs = backwardsTranslatePHI(sii->second, B, SB);
      //IFRs *ifrs = &sii->second;
      IFRsList.push_back(ifrs);
    }
  }
  return joinIFRs(IFRsList);
}

InsertDRDCalls::IFRs *
InsertDRDCalls::backwardsTranslatePHI(IFRs &ifrs,
				      BasicBlock &pred,
				      BasicBlock &succ) {
  IFRs *result = new IFRs();
  for (IFRs::iterator i = ifrs.begin(), e = ifrs.end(); i != e; i++) {
    Value *V = i->first;
    PHINode *P = dyn_cast<PHINode>(V);
    if (P != NULL && P->getParent() == &succ) {
      Value *PredV = P->getIncomingValueForBlock(&pred);
      (*result)[PredV] = i->second;
    } else {
      (*result)[V] = i->second;
    }
  }
  return result;
}

InsertDRDCalls::IFRs
InsertDRDCalls::joinIFRs
(std::list<InsertDRDCalls::IFRs *> &IFRsList) {
  if (IFRsList.empty()) {
    return IFRs();
  }

  std::list<IFRs *>::iterator i = IFRsList.begin();
  IFRs Result = **(i++);
  for ( ; i != IFRsList.end(); i++) {
    IFRs *CurrentIFR = *i;
    IFRs TempIFR;
    for(IFRs::iterator ii = CurrentIFR->begin();
	ii != CurrentIFR->end(); ii++) {
      Value *V = ii->first;
      IFRInfo *CurrentInfo = &ii->second;
      IFRs::iterator ri = Result.find(V);
      if (ri != Result.end()) {
	IFRInfo *ResultInfo = &ri->second;
	TempIFR[V].first = (IFRType) (ResultInfo->first & CurrentInfo->first);
	TempIFR[V].second = ResultInfo->second;
	TempIFR[V].second.insert(CurrentInfo->second.begin(),
				 CurrentInfo->second.end());
      }
    }
    Result = TempIFR;
  }
  return Result;
}

// Returns true if this instruction is a release action (e.g., a call
// to pthread_mutex_unlock)
bool InsertDRDCalls::isAcquire(Instruction &I) {
  if (CallInst *CI = dyn_cast<CallInst>(&I)) {
    Function *F = CI->getCalledFunction();
    if (!F) {
      return false;
    }

    if (F->getName() == "pthread_mutex_lock" ||
	F->getName() == "pthread_join" ||
	F->getName() == "pthread_rwlock_lock" ||
	F->getName() == "malloc" ||
	F->getName() == "calloc" ||
	F->getName() == "__cxa_guard_acquire") {
      return true;
    }

    StringRef Name = F->getName();
    if (Name == "pthread_mutex_lock"
	|| Name == "pthread_mutex_trylock"
	|| Name == "pthread_mutex_timedlock"
	|| Name == "pthread_rwlock_rdlock"
	|| Name == "pthread_rwlock_tryrdlock"
	|| Name == "pthread_rwlock_timedrdlock"
	|| Name == "pthread_rwlock_wrlock"
	|| Name == "pthread_rwlock_trywrlock"
	|| Name == "pthread_rwlock_timedwrlock"
	|| Name == "pthread_spin_lock"
	|| Name == "pthread_spin_trylock"
	|| Name == "pthread_join"
	|| Name == "malloc"
	|| Name == "calloc"
	|| Name == "__cxa_guard_acquire"
	|| Name == "_Znam"
	|| Name == "_Znwm") {
      return true;
    }
  }
  return false;
}

// Returns true if this instruction is a release action (e.g., a call
// to pthread_mutex_unlock)
bool InsertDRDCalls::isRelease(Instruction &I) {
  if (CallInst *CI = dyn_cast<CallInst>(&I)) {
    Function *F = CI->getCalledFunction();
    if (!F) {
      return false;
    }

    if (F->getName() == "pthread_mutex_unlock" ||
	F->getName() == "pthread_create" ||
	F->getName() == "free" ||
	F->getName() == "pthread_spin_unlock" ||
	F->getName() == "pthread_rwlock_unlock") {
      //      F->getName() == "_ZdlPv" ||
      //	F->getName() == "__cxa_guard_release") {
      return true;
    }
  }
  return false;
}

// Returns true if this instruction is a release action (e.g., a call
// to pthread_mutex_unlock)
bool InsertDRDCalls::isNone(Instruction &I) {
  if (CallInst *CI = dyn_cast<CallInst>(&I)) {
    Function *F = CI->getCalledFunction();
    if (!F) {
      return false;
    }

    if (F->getName() == "drand48" ||
	F->getName() == "erand48" ||
	F->getName() == "lrand48" ||
	F->getName() == "nrand48" ||
	F->getName() == "mrand48" ||
	F->getName() == "jrand48" ||
	F->getName() == "srand48" ||
	F->getName() == "seed48" ||
	F->getName() == "lcong48" ||
	F->getName() == "fwrite" ||
	F->getName() == "strtol" ||
	F->getName() == "fputc" ||
	F->getName() == "fflush" ||
	F->getName() == "strcpy" ||
	F->getName() == "log" ||
	F->getName() == "fread" ||
	F->getName() == "ferror" ||
	F->getName() == "feof" ||
	F->getName() == "fclose" ||
	F->getName() == "llvm.memset.p0i8.i64" ||
	F->getName() == "fopen" ||
	F->getName() == "fprintf") {
      return true;
    }

    StringRef Name = F->getName();
    if (
	Name == "fabs"
	     || Name == "log"
	     || Name == "sqrt"
	     || Name == "fprintf"
	     || Name == "exit"
	     || Name == "fwrite"
	     || Name == "llvm.memset.p0i8.i64"
	     || Name == "exp"
	     || Name == "puts"
	     || Name == "fflush"
	     || Name == "strcmp"
	     || Name == "atoi"
	     || Name == "printf"
	     || Name == "pthread_attr_init"
	     || Name == "sqrtf"
	     || Name == "fopen"
	     || Name == "fclose"
	     || Name == "pthread_mutexattr_init"
	     || Name == "fscanf"
	     || Name == "__cxa_atexit"
	     || Name == "_ZNSt8ios_base4InitC1Ev"
	     || Name == "_ZNSt8ios_base4InitD1Ev"
	     || Name == "pthread_cond_signal"
	     || Name == "pthread_cond_broadcast"
	     || Name == "llvm.memcpy.p0i8.p0i8.i64"
	     || Name == "lrand48"
	     || Name == "fputc"
	     || Name == "llvm.umul.with.overflow.i64"
	     || Name == "llvm.lifetime.start"
	     || Name == "llvm.lifetime.end"
	     || Name == "pthread_mutex_init"
	     || Name == "pthread_mutex_destroy"
	     || Name == "pthread_cond_destroy"
	     || Name == "pthread_cond_init"
	     || Name == "strcpy"
	     || Name == "srand48"
	     || Name == "feof"
	     || Name == "ferror"
	     || Name == "fread"
	     || Name == "pthread_barrier_init"
	     || Name == "pthread_barrier_destroy"
	     || Name == "_ZNSolsEPFRSoS_E"
	     || Name == "_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_"
	     || Name == "_ZNSirsERf"
	     || Name == "_ZNSt14basic_ifstreamIcSt11char_traitsIcEED1Ev"
	     || Name == "llvm.memmove.p0i8.p0i8.i64"
	     || Name == "__cxa_rethrow"
	     || Name == "__cxa_end_catch"
	     || Name == "_ZSt9terminatev"
	     || Name == "llvm.dbg.declare"
	     || Name == "__gxx_personality_v0"
	     || Name == "__cxa_begin_catch"
	     || Name == "llvm.expect.i64"
	     || Name == "_ZSt17__throw_bad_allocv"
	     || Name == "_ZSt20__throw_length_errorPKc"
	     || Name == "_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode"
	     || Name == "_ZNKSs5c_strEv"
	     || Name == "_ZNSt14basic_ifstreamIcSt11char_traitsIcEE7is_openEv"
	     || Name == "_ZStlsIcSt11char_traitsIcESaIcEERSt13basic_ostreamIT_T0_ES7_RKSbIS4_S5_T1_E"
	     || Name == "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc"
	     || Name == "cos"
	     || Name == "sin"
	     || Name == "_ZNSsC1EPKcRKSaIcE"
	     || Name == "_ZNSaIcEC1Ev"
	     || Name == "_ZNSsD1Ev"
	     || Name == "_ZNSaIcED1Ev"
	     || Name == "_ZNSsC1Ev"
	     || Name == "_ZNSsaSERKSs"
	     || Name == "_ZNSsC1ERKSs"
	     || Name == "_ZNSs6appendERKSs"
	     || Name == "_ZNSt18basic_stringstreamIcSt11char_traitsIcESaIcEEC1ESt13_Ios_Openmode"
	     || Name == "_ZStlsIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_St8_SetfillIS3_E"
	     || Name == "_ZStlsIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_St5_Setw"
	     || Name == "_ZNSolsEi"
	     || Name == "_ZNKSt18basic_stringstreamIcSt11char_traitsIcESaIcEE3strEv"
	     || Name == "_ZNSt18basic_stringstreamIcSt11char_traitsIcESaIcEED1Ev"
	     || Name == "_ZNSs6appendEPKc"
	     || Name == "__cxa_allocate_exception"
	     || Name == "__cxa_throw"
	     || Name == "_ZNSolsEj"
	     || Name == "_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode"
	     || Name == "_ZNSspLERKSs"
	     || Name == "_ZNSsixEm"
	     || Name == "_ZNKSs4sizeEv"
	     || Name == "_ZNSs9push_backEc"
	     || Name == "_ZNSt14basic_ofstreamIcSt11char_traitsIcEED1Ev"
	     || Name == "_ZSt5flushIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_"
	     || Name == "_ZNSolsEf"
	     || Name == "_ZNSt19basic_istringstreamIcSt11char_traitsIcESaIcEEC1ERKSsSt13_Ios_Openmode"
	     || Name == "_ZNSirsERi"
	     || Name == "_ZNKSt9basic_iosIcSt11char_traitsIcEE4failEv"
	     || Name == "_ZNSt19basic_istringstreamIcSt11char_traitsIcESaIcEED1Ev"
	     || Name == "llvm.uadd.with.overflow.i64"
	     || Name == "_ZNSt8bad_castD1Ev"
	     || Name == "__cxa_call_unexpected"
	     || Name == "__dynamic_cast"
	     || Name == "__cxa_bad_cast"
	     || Name == "llvm.eh.typeid.for"
	     || Name == "__cxa_get_exception_ptr"
	     || Name == "_ZNSt9exceptionD2Ev"
	     || Name == "llvm.dbg.value"
	     || Name == "_ZNSt15_List_node_base4hookEPS_"
	     || Name == "_ZNSi4readEPcl"
	     || Name == "llvm.pow.f64"
	     || Name == "pthread_attr_setdetachstate"
	     || Name == "pthread_attr_destroy"
	     || Name == "llvm.invariant.start"
	     || Name == "_ZNSt6localeD1Ev"
	     || Name == "_ZNSt13basic_filebufIcSt11char_traitsIcEEC1Ev"
	     || Name == "_ZNSt9basic_iosIcSt11char_traitsIcEE4initEPSt15basic_streambufIcS1_E"
	     || Name == "_ZNSt13basic_filebufIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode"
	     || Name == "_ZNSt9basic_iosIcSt11char_traitsIcEE5clearESt12_Ios_Iostate"
	     || Name == "_ZNSt8ios_baseC2Ev"
	     || Name == "_ZNSo5writeEPKcl"
	     || Name == "__assert_fail"
	     || Name == "llvm.stacksave"
	     || Name == "llvm.stackrestore"
	     || Name == "_ZNSo5flushEv"
	     || Name == "_ZNSt8ios_baseD2Ev"
	     || Name == "_ZNSt13basic_filebufIcSt11char_traitsIcEE5closeEv"
	     || Name == "_ZNSt12__basic_fileIcED1Ev"
	     || Name == "_ZNSo3putEc"
	     || Name == "memcmp"
	     || Name == "_ZSt16__throw_bad_castv"
	     || Name == "_ZSt16__ostream_insertIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_PKS3_l"
	     || Name == "strlen"
	     || Name == "_ZNSo9_M_insertIdEERSoT_"
	     || Name == "pthread_cancel"
	     || Name == "srandom"
	     || Name == "_ZNSs4_Rep10_M_destroyERKSaIcE"
	     || Name == "_ZStrsIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RSbIS4_S5_T1_E"
	     || Name == "_ZNSt9basic_iosIcSt11char_traitsIcEE4initEPSt15basic_streambufIcS1_E"
	     || Name == "_ZSt20__throw_out_of_rangePKc"
	     || Name == "_ZNKSs7compareEPKc"
	     || Name == "_ZNSs6assignERKSs"
	     || Name == "_ZNSi10_M_extractIjEERSiRT_"
	     || Name == "_ZSt18_Rb_tree_incrementPKSt18_Rb_tree_node_base"
	     || Name == "_ZSt18_Rb_tree_decrementPKSt18_Rb_tree_node_base"
	     || Name == "_ZSt18_Rb_tree_decrementPSt18_Rb_tree_node_base"
	     || Name == "_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_"
	     || Name == "_ZSt18_Rb_tree_incrementPSt18_Rb_tree_node_base"
	     || Name == "abort"
	     || Name == "access"
	     || Name == "acos"
	     || Name == "asin"
	     || Name == "atan"
	     || Name == "atan2"
	     || Name == "cbrt"
	     || Name == "ceil"
	     || Name == "close"
	     || Name == "closedir"
	     || Name == "ctime"
	     || Name == "__ctype_b_loc"
	     || Name == "__ctype_tolower_loc"
	     || Name == "__ctype_toupper_loc"
	     || Name == "__errno_location"
	     || Name == "execvp"
	     || Name == "_exit"
	     || Name == "exp2"
	     || Name == "fdopen"
	     || Name == "fgetc"
	     || Name == "fileno"
	     || Name == "finite"
	     || Name == "floor"
	     || Name == "floorf"
	     || Name == "fmod"
	     || Name == "fopen64"
	     || Name == "fork"
	     || Name == "fputs"
	     || Name == "fseeko64"
	     || Name == "ftello64"
	     || Name == "__fxstat64"
	     || Name == "getcwd"
	     || Name == "getenv"
	     || Name == "getpid"
	     || Name == "getpwnam"
	     || Name == "gettimeofday"
	     || Name == "gmtime"
	     || Name == "hypot"
	     || Name == "_IO_getc"
	     || Name == "_IO_putc"
	     || Name == "__isoc99_fscanf"
	     || Name == "__isoc99_sscanf"
	     || Name == "jpeg_calc_output_dimensions"
	     || Name == "jpeg_CreateCompress"
	     || Name == "jpeg_CreateDecompress"
	     || Name == "jpeg_destroy_compress"
	     || Name == "jpeg_destroy_decompress"
	     || Name == "jpeg_finish_compress"
	     || Name == "jpeg_finish_decompress"
	     || Name == "jpeg_read_header"
	     || Name == "jpeg_read_scanlines"
	     || Name == "jpeg_resync_to_restart"
	     || Name == "jpeg_set_defaults"
	     || Name == "jpeg_set_marker_processor"
	     || Name == "jpeg_set_quality"
	     || Name == "jpeg_simple_progression"
	     || Name == "jpeg_start_compress"
	     || Name == "jpeg_start_decompress"
	     || Name == "jpeg_std_error"
	     || Name == "jpeg_write_marker"
	     || Name == "jpeg_write_scanlines"
	     || Name == "ldexp"
	     || Name == "llvm.trap"
	     || Name == "llvm.va_end"
	     || Name == "llvm.va_start"
	     || Name == "localtime"
	     || Name == "log10"
	     || Name == "longjmp"
	     || Name == "lseek64"
	     || Name == "lstat"
	     || Name == "memchr"
	     || Name == "memcpy"
	     || Name == "mkstemp64"
	     || Name == "mmap64"
	     || Name == "msync"
	     || Name == "munmap"
	     || Name == "open64"
	     || Name == "opendir"
	     || Name == "pclose"
	     || Name == "perror"
	     || Name == "popen"
	     || Name == "pread64"
	     || Name == "pthread_mutexattr_destroy"
	     || Name == "pthread_self"
	     || Name == "pwrite64"
	     || Name == "qsort"
	     || Name == "rand"
	     || Name == "read"
	     || Name == "readdir"
	     || Name == "readdir64"
	     || Name == "remove"
	     || Name == "rename"
	     || Name == "rewind"
	     || Name == "_setjmp"
	     || Name == "setlocale"
	     || Name == "setvbuf"
	     || Name == "signal"
	     || Name == "sleep"
	     || Name == "snprintf"
	     || Name == "sprintf"
	     || Name == "srand"
	     || Name == "sscanf"
	     || Name == "strcasecmp"
	     || Name == "strcat"
	     || Name == "strchr"
	     || Name == "strcspn"
	     || Name == "__strdup"
	     || Name == "strerror"
	     || Name == "strftime"
	     || Name == "strncasecmp"
	     || Name == "strncmp"
	     || Name == "strncpy"
	     || Name == "strrchr"
	     || Name == "strspn"
	     || Name == "strstr"
	     || Name == "strtod"
	     || Name == "strtol"
	     || Name == "strtoul"
	     || Name == "symlink"
	     || Name == "sysconf"
	     || Name == "system"
	     || Name == "tan"
	     || Name == "time"
	     || Name == "times"
	     || Name == "ungetc"
	     || Name == "vfprintf"
	     || Name == "vsnprintf"
	     || Name == "waitpid"
	     || Name == "write"
	     || Name == "__xstat"
	|| Name == "__xstat64") {
      return true;
    }
  }
  return false;
}

void InsertDRDCalls::clearUndeclaredIFRs() {
  for (std::map<CallInst *, IFRs>::iterator i = CallIFRs.begin(),
	 e = CallIFRs.end(); i != e; i++) {
    CallInst *I = i->first;
    DominatorTree *DT = &getAnalysis<DominatorTree>
      (*I->getParent()->getParent());
    for (IFRs::iterator ii = i->second.begin(), ee = i->second.end();
	 ii != ee; ) {
      if (Instruction *Decl = dyn_cast<Instruction>(ii->first)) {
	if (!DT->dominates(Decl, I)) {
#ifdef INSERT_DECL_IFRS
	  DeclIFRs[Decl] = ii->second;
#endif
	  i->second.erase(ii++);
	} else {
	  ii++;
	}
      } else {
	ii++;
      }
    }
  }

  for (std::map<CallInst *, IFRs>::iterator i = ReleaseIFRs.begin(),
	 e = ReleaseIFRs.end(); i != e; i++) {
    CallInst *I = i->first;
    DominatorTree *DT = &getAnalysis<DominatorTree>
      (*I->getParent()->getParent());
    for (IFRs::iterator ii = i->second.begin(), ee = i->second.end();
	 ii != ee; ) {
      if (Instruction *Decl = dyn_cast<Instruction>(ii->first)) {
	if (!DT->dominates(Decl, I)) {
#ifdef INSERT_DECL_IFRS
	  DeclIFRs[Decl] = ii->second;
#endif
	  i->second.erase(ii++);
	} else {
	  ii++;
	}
      } else {
	ii++;
      }
    }
  }

  for (std::map<BasicBlock *, IFRs>::iterator i =
	 BasicBlockBackwardsIFRs.begin(), e = BasicBlockBackwardsIFRs.end();
       i != e; i++) {
    Instruction *I = i->first->begin();
    DominatorTree *DT = &getAnalysis<DominatorTree>
      (*I->getParent()->getParent());
    IFRs &ifrs = i->second;
    for (IFRs::iterator ii = ifrs.begin(), ee = ifrs.end(); ii != ee; ) {
      if (Instruction *Decl = dyn_cast<Instruction>(ii->first)) {
	if (I == Decl || (!DT->dominates(Decl, I))) {
#ifdef INSERT_DECL_IFRS
	  DeclIFRs[Decl] = ii->second;
#endif
	  ifrs.erase(ii++);
	} else {
	  ii++;
	}
      } else {
	ii++;
      }
    }
  }
}

void InsertDRDCalls::doForwardsAnalysis(Function &F) {
  // Construct a worklist of basic blocks to process
  std::set<BasicBlock *> Worklist;

  // Add entry block to worklist
  Worklist.insert(&F.getEntryBlock());

  // Pull a block off the worklist and process it
  while (!Worklist.empty()) {
    std::set<BasicBlock *>::iterator si = Worklist.begin();
    BasicBlock &B = **si;
    Worklist.erase(si);

    // Save the old exit values for this block, so we can track
    // whether we need to process its successors again. If this is
    // the first pass over this block, we will always process its
    // successors.
    std::map<BasicBlock *, std::map<Value *, IFRType> >::iterator i =
      BasicBlockForwardsIFRs.find(&B);
    std::map<Value *, IFRType> *IFRsOld;
    bool FirstPass = false;
    if (i == BasicBlockForwardsIFRs.end()) {
      // This is the first time this block has been processed, so we
      // will also need to process its successors
      FirstPass = true;
    } else {
      // This block has been processed before - save the old exit
      // information so we can compare when we've finished analyzing
      // it
      IFRsOld = &i->second;
    }

    std::map<Value *, IFRType> IFRsNew = getForwardsEntryIFRs(B);

    // Include the IFRs for this basic block
    IFRs &BackIFRs = BasicBlockBackwardsIFRs[&B];
    for (IFRs::iterator ii = BackIFRs.begin(); ii != BackIFRs.end();
	 ii++) {
      IFRsNew[ii->first] = IFRType(IFRsNew[ii->first] | ii->second.first);
    }

    for (BasicBlock::iterator bi = B.begin(); bi != B.end(); bi++) {
      if (CallInst *I = dyn_cast<CallInst>(bi)) {
	if (isRelease(*I)) {
	  // Release call - kill all IFRs, except the ones listed by
	  // the release.
	  IFRsNew.clear();
	  IFRs &BackIFRs = ReleaseIFRs[I];
	  for (IFRs::iterator ii = BackIFRs.begin(); ii != BackIFRs.end();
	       ii++) {
	    IFRsNew[ii->first] = ii->second.first;
	  }
	} else if (isNone(*I)) {
	  // No IFRs killed, no new IFRs
	} else if (isAcquire(*I)) {
	  // acquire call - save the forward IFRs
	  AcquireCallForwardsIFRs[I] = IFRsNew;

	  // and merge in the call's IFRs
	  IFRs &BackIFRs = CallIFRs[I];
	  for (IFRs::iterator ii = BackIFRs.begin(); ii != BackIFRs.end();
	       ii++) {
	    IFRsNew[ii->first] = IFRType(IFRsNew[ii->first] | ii->second.first);
	  }
	} else {
	  // unknown call - kill all IFRs, except those listed by the
	  // call.
	  IFRsNew.clear();
	  IFRs &BackIFRs = CallIFRs[I];
	  for (IFRs::iterator ii = BackIFRs.begin(); ii != BackIFRs.end();
	       ii++) {
	    IFRsNew[ii->first] = ii->second.first;
	  }
	}
      } else if (dyn_cast<InvokeInst>(bi)) {
	IFRsNew.clear();
      }

#ifdef INSERT_DECL_IFRS
      Instruction *I = bi;
      IFRs::iterator ii = DeclIFRs.find(I);
      if (ii != DeclIFRs.end()) {
 	// merge in this declaration's IFR
 	IFRsNew[I] = ii->second.first;
      }
#endif
    }

    // Now IFRsNew represents the final value of IFRs for this block -
    // has it been updated by this pass?
    if (FirstPass || IFRsNew != *IFRsOld) {
      BasicBlockForwardsIFRs[&B] = IFRsNew;

      // Add successors to worklist
      for (succ_iterator si = succ_begin(&B), se = succ_end(&B);
	   si != se; si++) {
	BasicBlock *SB = *si;
	Worklist.insert(SB);
      }
    }
  }
}

std::map<Value *, InsertDRDCalls::IFRType>
InsertDRDCalls::getForwardsEntryIFRs(BasicBlock &B) {
  if (&B == &B.getParent()->getEntryBlock()) {
    IFRs &ifrs = BasicBlockBackwardsIFRs[&B];
    std::map<Value *, IFRType> *result = new std::map<Value *, IFRType>();
    for (IFRs::iterator i = ifrs.begin(); i != ifrs.end(); i++) {
      Value *V = i->first;
      IFRType T = i->second.first;
      (*result)[V] = T;
    }
    return *result;
  }

  std::list<std::map<Value *, IFRType> *> IFRsList;
  for (pred_iterator pi = pred_begin(&B), pe = pred_end(&B);
       pi != pe; pi++) {
    BasicBlock &PB = **pi;
    std::map<BasicBlock *, std::map<Value *, IFRType> >::iterator pii =
      BasicBlockForwardsIFRs.find(&PB);
    if (pii != BasicBlockForwardsIFRs.end()) {
      std::map<Value *, IFRType> *ifrs =
	forwardsTranslatePHI(pii->second, PB, B);
      //std::map<Value *, IFRType> *ifrs = &pii->second, PB, B;
      IFRsList.push_back(ifrs);
    }
  }
  return joinForwardsIFRs(IFRsList);
}

std::map<Value *, InsertDRDCalls::IFRType> *
InsertDRDCalls::forwardsTranslatePHI(std::map<Value *, IFRType> &ifrs,
				     BasicBlock &pred,
				     BasicBlock &succ) {
  std::map<Value *, IFRType> *result = new std::map<Value *, IFRType>(ifrs);
  BasicBlock::iterator i = succ.begin();
  BasicBlock::iterator e = BasicBlock::iterator(succ.getFirstNonPHI());
  while (i != e) {
    if (PHINode *P = dyn_cast<PHINode>(i)) {
      for (PHINode::block_iterator j = P->block_begin();
	   j != P->block_end(); j++) {
	if (*j == &pred) {
	  Value *V = P->getIncomingValueForBlock(&pred);
	  std::map<Value *, IFRType>::iterator fi = result->find(V);
	  if (fi != result->end()) {
	    IFRType type = fi->second;
	    result->erase(V);
	    (*result)[P] = type;
	  }
	}
      }
    }
    i++;
  }
  return result;
}

std::map<Value *, InsertDRDCalls::IFRType>
InsertDRDCalls::joinForwardsIFRs
(std::list<std::map<Value *, InsertDRDCalls::IFRType> *> &IFRsList) {
  if (IFRsList.empty()) {
    return std::map<Value *, IFRType>();
  }

  std::list<std::map<Value *, IFRType> *>::iterator i = IFRsList.begin();
  std::map<Value *, IFRType> Result = **(i++);
  for ( ; i != IFRsList.end(); i++) {
    std::map<Value *, IFRType> &CurrentIFR = **i;
    std::map<Value *, IFRType> TempIFR;
    for(std::map<Value *, IFRType>::iterator ii = CurrentIFR.begin();
	ii != CurrentIFR.end(); ii++) {
      Value *V = ii->first;
      std::map<Value *, IFRType>::iterator ri = Result.find(V);
      if (ri != Result.end()) {
	TempIFR[V] = (IFRType) (ri->second & ii->second);
      }
    }
    Result = TempIFR;
  }
  return Result;
}

void InsertDRDCalls::findBasicBlockIFRs(Function &F) {
  for (Function::iterator i = F.begin(); i != F.end(); i++) {
    BasicBlock *B = i;
    std::map<Value *, IFRType> &ForwardsIFRs = BasicBlockForwardsIFRs[B];

    // Iterate through the blocks successors
    for (succ_iterator si = succ_begin(B); si != succ_end(B); si++) {
      BasicBlock *SB = *si;

      IFRs &BackwardsIFRs = BasicBlockBackwardsIFRs[SB];

      // Compare the forwards IFRs for this block with the backwards
      // IFRs for its successor
      for (IFRs::iterator ii = BackwardsIFRs.begin(); ii != BackwardsIFRs.end();
	   ii++) {
	Value *V = ii->first;
	IFRType BackwardsType = ii->second.first;
	std::map<Value *, IFRType>::iterator fi = ForwardsIFRs.find(V);
	if (fi == ForwardsIFRs.end()) {
	  // This IFR was not active in the current block; start a new
	  // IFR in the successor.
	  BasicBlockIFRs[B][SB][V] = ii->second;
	} else {
	  IFRType ForwardsType = fi->second;
	  if (BackwardsType == MustWriteIFR && ForwardsType == MayWriteIFR) {
	    // This IFR was weak in the current block; start a new
	    // strong IFR in the successor.
	    BasicBlockIFRs[B][SB][V] = ii->second;
	  }
	}
      }
    }
  }
}

void InsertDRDCalls::pruneAcquireIFRs() {
  // AcquireCallForwardsIFRs represents the set of IFRs that are
  // already active when we hit an IFR. We can prune these from the
  // set of IFRs for that acquire.
  for (std::map<CallInst *, std::map<Value *, IFRType> >::iterator i =
	 AcquireCallForwardsIFRs.begin(); i != AcquireCallForwardsIFRs.end();
       i++) {
    CallInst *I = i->first;
    std::map<Value *, IFRType> &ForwardsIFRs = i->second;
    IFRs &BackwardsIFRs = CallIFRs[I];
    for (IFRs::iterator ii = BackwardsIFRs.begin();
	 ii != BackwardsIFRs.end(); ) {
      Value *V = ii->first;
      IFRType BackwardsType = ii->second.first;
      std::map<Value *, IFRType>::iterator fi = ForwardsIFRs.find(V);
      if (fi != ForwardsIFRs.end()) {
	// V is already active.
	IFRType ForwardsType = fi->second;
	if (ForwardsType == MustWriteIFR || BackwardsType == MayWriteIFR) {
	  BackwardsIFRs.erase(ii++);
	} else {
	  ii++;
	}
      }	else {
	ii++;
      }
    }
  }
}

void InsertDRDCalls::insertBeginIFRCalls(Module &M) {
  Function *BeginIFR = createBeginIFRFunction(M);

  insertCallIFRs(M, BeginIFR);

#ifdef INSERT_DECL_IFRS
  Function *BeginReadIFR = createBeginReadIFRFunction(M);
  Function *BeginWriteIFR = createBeginWriteIFRFunction(M);
  insertDeclIFRs(M, BeginReadIFR, BeginWriteIFR);
#endif

  insertBasicBlockIFRs(M, BeginIFR);


}

Function *InsertDRDCalls::createBeginIFRFunction(Module &M) {
  // Construct new function named, "___begin_ifrs".
  std::string NewName = "IFRit_begin_ifrs";

  // Construct a new function type from the type of the old function.
  LLVMContext &Context = M.getContext();

  // The return type is void.
  Type *ReturnType = Type::getVoidTy(Context);

  // It takes three int arguments, plus a varargs.
  std::vector<Type *> ParamTypes;
  ParamTypes.push_back(Type::getInt64Ty(Context));
  ParamTypes.push_back(Type::getInt64Ty(Context));
  ParamTypes.push_back(Type::getInt64Ty(Context));

  // The full function type.
  FunctionType *NewType = FunctionType::get(ReturnType, ArrayRef<Type *>(ParamTypes), true);

  // Insert a declaration of the custom function.
  Function *NewFunction = cast<Function>
    (M.getOrInsertFunction(NewName, NewType));
  //std::cerr << "Inserted function: " << NewName << std::endl;

  // This function never throws an exceprion.
  NewFunction->setDoesNotThrow();

  // Set the calling convention.
  NewFunction->setCallingConv(CallingConv::C);

  return NewFunction;
}

Function *InsertDRDCalls::createBeginReadIFRFunction(Module &M) {
  // Construct new function name.
  std::string NewName = "IFRit_begin_one_read_ifr";

  // Construct a new function type from the type of the old function.
  LLVMContext &Context = M.getContext();

  // The return type is void.
  Type *ReturnType = Type::getVoidTy(Context);

  // It takes two int arguments.
  std::vector<Type *> ParamTypes;
  ParamTypes.push_back(Type::getInt64Ty(Context));
  ParamTypes.push_back(Type::getInt64PtrTy(Context));

  // The full function type.
  FunctionType *NewType = FunctionType::get(ReturnType, ArrayRef<Type *>(ParamTypes), false);

  // Insert a declaration of the custom function.
  Function *NewFunction = cast<Function>
    (M.getOrInsertFunction(NewName, NewType));

  // This function never throws an exception.
  NewFunction->setDoesNotThrow();

  // Set the calling convention.
  NewFunction->setCallingConv(CallingConv::C);

  return NewFunction;
}

Function *InsertDRDCalls::createBeginWriteIFRFunction(Module &M) {
  // Construct new function name.
  std::string NewName = "IFRit_begin_one_write_ifr";

  // Construct a new function type from the type of the old function.
  LLVMContext &Context = M.getContext();

  // The return type is void.
  Type *ReturnType = Type::getVoidTy(Context);

  // It takes two int arguments.
  std::vector<Type *> ParamTypes;
  ParamTypes.push_back(Type::getInt64Ty(Context));
  ParamTypes.push_back(Type::getInt64PtrTy(Context));

  // The full function type.
  FunctionType *NewType = FunctionType::get(ReturnType, ArrayRef<Type *>(ParamTypes), false);

  // Insert a declaration of the custom function.
  Function *NewFunction = cast<Function>
    (M.getOrInsertFunction(NewName, NewType));

  // This function never throws an exception.
  NewFunction->setDoesNotThrow();

  // Set the calling convention.
  NewFunction->setCallingConv(CallingConv::C);

  return NewFunction;
}

#ifdef INSERT_CHECK_IFRS
Function *InsertDRDCalls::createCheckIFRFunction(Module &M) {
  // Construct new function name.
  std::string NewName = "IFRit_check_ifr";

  // Construct a new function type from the type of the old function.
  LLVMContext &Context = M.getContext();

  // The return type is void.
  Type *ReturnType = Type::getVoidTy(Context);

  // It takes two int arguments.
  std::vector<Type *> ParamTypes;
  ParamTypes.push_back(Type::getInt64Ty(Context));
  ParamTypes.push_back(Type::getInt64PtrTy(Context));
  ParamTypes.push_back(Type::getInt64Ty(Context));

  // The full function type.
  FunctionType *NewType = FunctionType::get(ReturnType,
					    ArrayRef<Type *>(ParamTypes),
					    false);

  // Insert a declaration of the custom function.
  Function *NewFunction = cast<Function>
    (M.getOrInsertFunction(NewName, NewType));

  // This function never throws an exception.
  NewFunction->setDoesNotThrow();

  // Set the calling convention.
  NewFunction->setCallingConv(CallingConv::C);

  return NewFunction;
}
#endif

void InsertDRDCalls::insertCallIFRs(Module &M,
				    Function *BeginIFR) {
  // Now insert calls to ___begin_ifr all over the place.
  for (std::map<CallInst *, IFRs>::iterator i =
	 CallIFRs.begin(), e = CallIFRs.end(); i != e; i++) {
    CallInst *I = i->first;
    IFRs *CurrentIFRs = &i->second;

    if (CurrentIFRs->empty()) {
      continue;
    }

    // For each IFR, pass an extra argument to the function
    std::vector<std::pair<Value *,
      IFRInfo *> > MayWriteIFRs;
    std::vector<std::pair<Value *,
      IFRInfo *> > MustWriteIFRs;
    for(IFRs::iterator ii = CurrentIFRs->begin();
	ii != CurrentIFRs->end(); ii++) {
      Value *V = ii->first;
      IFRInfo *CurrentInfo = &ii->second;
      assert (V->getType()->isFirstClassType());

      if (CurrentInfo->first == MayWriteIFR) {
	MayWriteIFRs.push_back
	  (std::pair<Value *,
	   IFRInfo *>(V, CurrentInfo));
      } else {
	MustWriteIFRs.push_back
	  (std::pair<Value *,
	   IFRInfo *>(V, CurrentInfo));
      }
    }

    assert(MayWriteIFRs.size() > 0 || MustWriteIFRs.size() > 0);

    unsigned int id = counter++;

    PrintIFRInfo(id, I, &MayWriteIFRs, true, false, IFRCallPlacement);
    PrintIFRInfo(id, I, &MustWriteIFRs, true, false, IFRCallPlacement);

    std::vector<Value *> Args;

    // IFR ID
    ConstantInt *idArg = ConstantInt::get
      (M.getContext(), APInt(64, id));
    Args.push_back(idArg);

    // Number of may-write IFRs
    ConstantInt *numMayWriteArg = ConstantInt::get
      (M.getContext(), APInt(64, MayWriteIFRs.size()));
    Args.push_back(numMayWriteArg);

    // Number of must-write IFRs
    ConstantInt *numMustWriteArg = ConstantInt::get
      (M.getContext(), APInt(64, MustWriteIFRs.size()));
    Args.push_back(numMustWriteArg);

    // May-write IFRs
    for (std::vector<std::pair<Value *,
	   IFRInfo *> >::iterator ii =
	   MayWriteIFRs.begin(); ii != MayWriteIFRs.end(); ii++) {
      Args.push_back(ii->first);
    }

    // Must-write IFRs
    for (std::vector<std::pair<Value *, IFRInfo *> >::iterator ii =
	   MustWriteIFRs.begin(); ii != MustWriteIFRs.end(); ii++) {
      Args.push_back(ii->first);
    }

    // Insert ___begin_ifrs2 call just after the call instruction.
    assert (!I->isTerminator());
    BasicBlock::iterator j = BasicBlock::iterator(I);
    j++;
    CallInst *NewInst = CallInst::Create(BeginIFR, ArrayRef<Value *>(Args), "",
					 j);
    NewInst->setDoesNotThrow();
    NewInst->setCallingConv(CallingConv::C);
  }
}

void InsertDRDCalls::insertBasicBlockIFRs(Module &M,
					  Function *BeginIFR) {
  for (std::map<BasicBlock *, std::map<BasicBlock *,
	 IFRs> >::iterator i =
	 BasicBlockIFRs.begin(), e = BasicBlockIFRs.end();
       i != e; i++) {
    BasicBlock *PB = i->first;
    std::map<BasicBlock *, IFRs> &SuccIFRs
      = i->second;

    for (std::map<BasicBlock *, IFRs>::iterator ii =
	   SuccIFRs.begin(), ee = SuccIFRs.end(); ii != ee; ii++) {
      BasicBlock *SB = ii->first;

      IFRs *CurrentIFRs = &ii->second;

      // For each IFR, pass an extra argument to the function
      std::vector<std::pair<Value *,
	IFRInfo *> > MayWriteIFRs;
      std::vector<std::pair<Value *,
	IFRInfo *> > MustWriteIFRs;
      for(IFRs::iterator iii = CurrentIFRs->begin();
	  iii != CurrentIFRs->end(); iii++) {
	Value *V = iii->first;
	IFRInfo *CurrentInfo = &iii->second;

	if (CurrentInfo->first == MayWriteIFR) {
	  MayWriteIFRs.push_back
	    (std::pair<Value *,
	     IFRInfo *>(V, CurrentInfo));
	} else {
	  MustWriteIFRs.push_back
	    (std::pair<Value *,
	     IFRInfo *>(V, CurrentInfo));
	}
      }

      unsigned int id = counter++;

      PrintIFRInfo(id, SB->begin(), &MayWriteIFRs, true, true, IFRBBPlacement);
      PrintIFRInfo(id, SB->begin(), &MustWriteIFRs, true, true, IFRBBPlacement);

      std::vector<Value *> Args;

      // IFR ID
      ConstantInt *idArg = ConstantInt::get
	(M.getContext(), APInt(64, id));
      Args.push_back(idArg);

      // Number of may-write IFRs
      ConstantInt *numMayWriteArg = ConstantInt::get
	(M.getContext(), APInt(64, MayWriteIFRs.size()));
      Args.push_back(numMayWriteArg);

      // Number of must-write IFRs
      ConstantInt *numMustWriteArg = ConstantInt::get
	(M.getContext(), APInt(64, MustWriteIFRs.size()));
      Args.push_back(numMustWriteArg);

      // May-write IFRs
      for (std::vector<std::pair<Value *,
	     IFRInfo *> >::iterator ii =
	     MayWriteIFRs.begin(); ii != MayWriteIFRs.end(); ii++) {
	Args.push_back(ii->first);
      }

      // Must-write IFRs
      for (std::vector<std::pair<Value *,
	     IFRInfo *> >::iterator ii =
	     MustWriteIFRs.begin(); ii != MustWriteIFRs.end(); ii++) {
	Args.push_back(ii->first);
      }

      // Three cases: (1) if the predecessor block has only one
      // successor, add a ___begin_ifr call at the end of the
      // predecessor block.
      Instruction *I;
      if (PB->getTerminator()->getNumSuccessors() == 1) {
	I = PB->getTerminator();
	assert (((TerminatorInst *) I)->getSuccessor(0) == SB);
      }
      // (2) If the successor block has only one predecessor, insert a
      // ___begin_ifr call at the beginning of the successor block.
      else if (SB->getSinglePredecessor()) {
	assert (SB->getSinglePredecessor() == PB);
	I = SB->getFirstInsertionPt();
      }
      // (3) This is a critical edge, but the destination is a landing
      // pad. We cannot split the critical edge.
      else if (SB->isLandingPad()) {
	I = SB->getFirstInsertionPt();
      }      
      // (4) Otherwise this is a critical edge - split the edge by
      // inserting a new basic block.
      else {

	TerminatorInst *TI = PB->getTerminator();
	unsigned idx = -1; //GetSuccessorNumber(PB, SB);
        int i = 0; 
        for(i = 0; i < TI->getNumSuccessors(); i++){

          if( TI->getSuccessor(i) == SB ){
            idx = i;
          }

        }
        if( idx == -1 ){
          /*Could not determine which successor of TI SB was*/
          continue;
        }
	BasicBlock *NewBlock = SplitCriticalEdge(TI, idx, this);
	if (!NewBlock) {
	  // The edge could not be split - probably because the
	  // successor is a landing pad block - ignore for now.
	  continue;
	}
	I = NewBlock->getTerminator();

      }
      CallInst *NewInst = CallInst::Create(BeginIFR, ArrayRef<Value *>(Args),
					   "", I);
      NewInst->setDoesNotThrow();
      NewInst->setCallingConv(CallingConv::C);
    }
  }

  // Also insert IFR calls for the entry block (which has no
  // predecessors).
  for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
    Function *F = mi;
    if (F->size() == 0) continue;
    BasicBlock *B = &F->getEntryBlock();
    std::map<BasicBlock *, IFRs>::iterator ii =
      BasicBlockBackwardsIFRs.find(B);
    if (ii != BasicBlockBackwardsIFRs.end()) {
      IFRs *CurrentIFRs = &ii->second;
      if (CurrentIFRs->size() == 0) {
	continue;
      }

      // For each IFR, pass an extra argument to the function
      std::vector<std::pair<Value *,
	IFRInfo *> > MayWriteIFRs;
      std::vector<std::pair<Value *,
	IFRInfo *> > MustWriteIFRs;
      for(IFRs::iterator iii = CurrentIFRs->begin();
	  iii != CurrentIFRs->end(); iii++) {
	Value *V = iii->first;
	IFRInfo *CurrentInfo = &iii->second;

	if (CurrentInfo->first == MayWriteIFR) {
	  MayWriteIFRs.push_back
	    (std::pair<Value *,
	     IFRInfo *>(V, CurrentInfo));
	} else {
	  MustWriteIFRs.push_back
	    (std::pair<Value *,
	     IFRInfo *>(V, CurrentInfo));
	}
      }

      unsigned int id = counter++;

      PrintIFRInfo(id, B->begin(), &MayWriteIFRs, true, true, IFRBBPlacement);
      PrintIFRInfo(id, B->begin(), &MustWriteIFRs, true, true, IFRBBPlacement);

      std::vector<Value *> Args;

      // IFR ID
      ConstantInt *idArg = ConstantInt::get
	(M.getContext(), APInt(64, id));
      Args.push_back(idArg);

      // Number of may-write IFRs
      ConstantInt *numMayWriteArg = ConstantInt::get
	(M.getContext(), APInt(64, MayWriteIFRs.size()));
      Args.push_back(numMayWriteArg);

      // Number of must-write IFRs
      ConstantInt *numMustWriteArg = ConstantInt::get
	(M.getContext(), APInt(64, MustWriteIFRs.size()));
      Args.push_back(numMustWriteArg);

      // May-write IFRs
      for (std::vector<std::pair<Value *,
	     IFRInfo *> >::iterator ii =
	     MayWriteIFRs.begin(); ii != MayWriteIFRs.end(); ii++) {
	Args.push_back(ii->first);
      }

      // Must-write IFRs
      for (std::vector<std::pair<Value *,
	     IFRInfo *> >::iterator ii =
	     MustWriteIFRs.begin(); ii != MustWriteIFRs.end(); ii++) {
	Args.push_back(ii->first);
      }

      // Insert at beginning of block
      Instruction *I = B->getFirstInsertionPt();
      CallInst *NewInst = CallInst::Create(BeginIFR,
					   ArrayRef<Value *>(Args),
					   "", I);
      NewInst->setDoesNotThrow();
      NewInst->setCallingConv(CallingConv::C);
    }
  }
}

#ifdef INSERT_DECL_IFRS
void InsertDRDCalls::insertDeclIFRs(Module &M, Function *BeginReadIFR,
				    Function *BeginWriteIFR) {
  for (IFRs::iterator i = DeclIFRs.begin(), e = DeclIFRs.end(); i != e; i++) {
    Instruction *I = (Instruction *) i->first;
    IFRInfo &Info = i->second;
    Function *BeginIFR = Info.first == MayWriteIFR ?
      BeginReadIFR : BeginWriteIFR;

    // Insert begin_ifrs call just after the declaration.
    assert(!I->isTerminator());
    Instruction *insertBefore;
    Instruction *firstInsertionPt = I->getParent()->getFirstInsertionPt();
    BasicBlock::iterator j = I->getParent()->begin();
    while (true) {
      if ((Instruction *) j == firstInsertionPt) {
	// I is past the first insertion point.
	j = BasicBlock::iterator(I);
	j++;
	insertBefore = j;
	break;
      } else if ((Instruction *) j == I) {
	// I is before the first valid insertion point - e.g. a PHI
	// node.
	insertBefore = firstInsertionPt;
	break;
      }
      j++;
    }

    // Create a cast instruction.
    BitCastInst *Cast =
      new BitCastInst(I, Type::getInt64PtrTy(M.getContext()),
		      "", insertBefore);

    // Construct the arguments to begin_ifrs.
    unsigned int id = counter++;
    std::vector<std::pair<Value *, IFRInfo *> > printInfo;
    printInfo.push_back(std::pair<Value *, IFRInfo *>(I, &Info));
    PrintIFRInfo(id, I, &printInfo, true, false, IFRDeclPlacement);

    std::vector<Value *> Args;

    // IFR ID
    ConstantInt *idArg = ConstantInt::get
      (M.getContext(), APInt(64, id));
    Args.push_back(idArg);

    // Single IFR
    Args.push_back(Cast);

    // Create call instruction
    CallInst *NewInst = CallInst::Create(BeginIFR, ArrayRef<Value *>(Args), "",
					 insertBefore);
    NewInst->setDoesNotThrow();
    NewInst->setCallingConv(CallingConv::C);
    if (MDNode *N = I->getMetadata("dbg")) {
      NewInst->setMetadata("dbg", N);
    }
  }
}

// void InsertDRDCalls::insertDeclIFRs(Module &M, Function *BeginIFR) {
//   for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
//     for (Function::iterator fi = mi->begin(); fi != mi->end(); fi++) {
//       BasicBlock *B = fi;
//       std::vector<Instruction *> MayWriteIFRs;
//       std::vector<Instruction *> MustWriteIFRs;
//       for (BasicBlock::iterator bi = B->begin(); bi != B->end(); bi++) {
// 	Instruction *I = bi;
// 	IFRs::iterator i = DeclIFRs.find(I);
// 	if (i != DeclIFRs.end()) {
// 	  if (i->second.first == MayWriteIFR) {
// 	    MayWriteIFRs.push_back(I);
// 	  } else {
// 	    MustWriteIFRs.push_back(I);
// 	  }
// 	}
//       }

//       unsigned int id = counter++;

//       std::vector<Value *> Args;

//       // IFR ID
//       ConstantInt *idArg = ConstantInt::get
// 	(M.getContext(), APInt(64, id));
//       Args.push_back(idArg);

//       // Number of may-write IFRs
//       ConstantInt *numMayWriteArg = ConstantInt::get
// 	(M.getContext(), APInt(64, MayWriteIFRs.size()));
//       Args.push_back(numMayWriteArg);

//       // Number of must-write IFRs
//       ConstantInt *numMustWriteArg = ConstantInt::get
// 	(M.getContext(), APInt(64, MustWriteIFRs.size()));
//       Args.push_back(numMustWriteArg);

//       // May-write IFRs
//       for (std::vector<Instruction *>::iterator ii = MayWriteIFRs.begin();
// 	   ii != MayWriteIFRs.end(); ii++) {
// 	Args.push_back(*ii);
//       }

//       // Must-write IFRs
//       for (std::vector<Instruction *>::iterator ii = MustWriteIFRs.begin();
// 	   ii != MustWriteIFRs.end(); ii++) {
// 	Args.push_back(*ii);
//       }

//       // Insert ___begin_ifrs2 call just after the call instruction.
//       CallInst *NewInst = CallInst::Create(BeginIFR,
// 					   ArrayRef<Value *>(Args), "",
// 					   B->getTerminator());
//       NewInst->setDoesNotThrow(true);
//       NewInst->setCallingConv(CallingConv::C);
//     }
//   }
// }
#endif

void InsertDRDCalls::instrumentReleaseCalls
(Module &M, std::string Name) {
  Function *Old = M.getFunction(Name);
  if (Old) {
    // Construct new function name, e.g. "IFRit_pthread_mutex_lock".
    std::string NewName = "IFRit_" + Name;

    // Construct a new function type from the type of the old function.
    FunctionType *NewType = constructNewFunctionType(Old, true);

    // Insert a declaration of the custom function.
    Function *New = cast<Function>
      (M.getOrInsertFunction(NewName, NewType, Old->getAttributes()));
    //std::cerr << "Inserted function: " << NewName << std::endl;

    // This function never throws an exceprion.
    New->setDoesNotThrow();

    // Set the calling convention
    New->setCallingConv(CallingConv::C);

    // Replace all calls to pthread_lock with the new functions.
    replaceAllCalls(M, Old, New, true);
  }
}

FunctionType *
InsertDRDCalls::constructNewFunctionType(Function *F, bool UseIFRs) {
  const FunctionType *OldType = F->getFunctionType();

  std::vector<Type *> ParamTypes;

  for (FunctionType::param_iterator i = OldType->param_begin(),
	 e = OldType->param_end(); i != e; i++) {
    Type *Param = *i;
    ParamTypes.push_back(Param);
  }

  // ParamTypes.push_back(Type::getInt64Ty(F->getParent()->getContext()));

  if (UseIFRs) {
    ParamTypes.push_back(Type::getInt64Ty(F->getParent()->getContext()));
    ParamTypes.push_back(Type::getInt64Ty(F->getParent()->getContext()));
  }

  return FunctionType::get(OldType->getReturnType(),
			   ArrayRef<Type *>(ParamTypes), UseIFRs);
}

void
InsertDRDCalls::replaceAllCalls(Module &M, Function *Old,
				Function *New, bool UseIFRs) {
  // Replace calls to the old function with a calls to the new
  // function.
  for (Value::use_iterator i = Old->use_begin(),
	 e = Old->use_end(); i != e; ++i) {
    CallSite CS(cast<Value>(*i));
    if (CS && CS.getCalledFunction() == Old) {
      // Push original arguments onto the arguments list.
      std::vector<Value *> Args;
      for (User::const_op_iterator ai = CS.arg_begin(), ae = CS.arg_end(); ai != ae;
	   ai++) {
	Args.push_back(*ai);
      }

      unsigned int id = counter++;

      // // IFR ID
      // ConstantInt *idArg = ConstantInt::get
      // 	(M.getContext(), APInt(64, id));
      // Args.push_back(idArg);

      if (UseIFRs) {
	// Check to see if there are any IFRs for this call.
	std::map<CallInst *, IFRs>::iterator ii
	  = ReleaseIFRs.end();
	if (CS.isCall()) {
	  ii = ReleaseIFRs.find(cast<CallInst>(CS.getInstruction()));
	}
	if (ii != ReleaseIFRs.end()) {
	  IFRs *CurrentIFRs = &ii->second;

	  // For each IFR, pass an extra argument to the function
	  std::vector<std::pair<Value *,
	    IFRInfo *> > MayWriteIFRs;
	  std::vector<std::pair<Value *,
	    IFRInfo *> > MustWriteIFRs;
	  for(IFRs::iterator iii =
		CurrentIFRs->begin(); iii != CurrentIFRs->end(); iii++) {
	    Value *V = iii->first;
	    IFRInfo *CurrentInfo = &iii->second;

	    if (CurrentInfo->first == MayWriteIFR) {
	      MayWriteIFRs.push_back
		(std::pair<Value *, IFRInfo *>
		 (V, CurrentInfo));
	    } else {
	      MustWriteIFRs.push_back
		(std::pair<Value *, IFRInfo *>
		 (V, CurrentInfo));
	    }
	  }

	  // Number of may-write IFRs
	  ConstantInt *numMayWriteArg = ConstantInt::get
	    (M.getContext(), APInt(64, MayWriteIFRs.size()));
	  Args.push_back(numMayWriteArg);

	  // Number of must-write IFRs
	  ConstantInt *numMustWriteArg = ConstantInt::get
	    (M.getContext(), APInt(64, MustWriteIFRs.size()));
	  Args.push_back(numMustWriteArg);

	  // May-write IFRs
	  for (std::vector<std::pair<Value *,
	       IFRInfo *> >::iterator iii =
	       MayWriteIFRs.begin(); iii != MayWriteIFRs.end(); iii++) {
	    Args.push_back(iii->first);
	  }

	  // Must-write IFRs
	  for (std::vector<std::pair<Value *,
	       IFRInfo *> >::iterator iii =
	       MustWriteIFRs.begin(); iii != MustWriteIFRs.end(); iii++) {
	    Args.push_back(iii->first);
	  }

	  if (MayWriteIFRs.size() || MustWriteIFRs.size()) {
	    PrintIFRInfo(id, CS.getInstruction(), &MayWriteIFRs, false, true, IFRReleasePlacement);
	    PrintIFRInfo(id, CS.getInstruction(), &MustWriteIFRs, false, true, IFRReleasePlacement);
	  } else {
	    PrintIFRInfo(id, CS.getInstruction(), NULL, false, true, IFRReleasePlacement);
	  }
	} else {
	  // Replace the call with a call to ___function(..., 0, 0) so
	  // that any active IFRs get killed.
	  ConstantInt *zeroArg = ConstantInt::get(M.getContext(),
						  APInt(64, 0));
	  Args.push_back(zeroArg);
	  Args.push_back(zeroArg);

	  PrintIFRInfo(id, CS.getInstruction(), NULL, false, true, IFRReleasePlacement);
	}
      }

      Instruction *NewInst;
      if (CS.isCall()) {
	CallInst *Call = CallInst::Create(New, ArrayRef<Value *>(Args));
	Call->setDoesNotThrow();
	Call->setCallingConv(CallingConv::C);
	NewInst = Call;
      } else if (CS.isInvoke()) {
	InvokeInst *II = cast<InvokeInst>(CS.getInstruction());
	InvokeInst *Invoke = InvokeInst::Create(New, II->getNormalDest(),
						II->getUnwindDest(),
						ArrayRef<Value *>(Args));
	Invoke->setDoesNotThrow();
	Invoke->setCallingConv(CallingConv::C);
	NewInst = Invoke;
      }

      BasicBlock::iterator bbi(CS.getInstruction());
      ReplaceInstWithInst(CS.getInstruction()->getParent()->getInstList(),
			  bbi, NewInst);
    }
  }
}

void InsertDRDCalls::PrintIFRInfo
(unsigned long id,
 Instruction *I,
 std::vector<std::pair<Value *,
 IFRInfo *> > *CurrentIFRs,
 bool Start, bool Before, IFRPlacement Placement) {

  if (CurrentIFRs) {
    for (std::vector<std::pair<Value *,
			       IFRInfo *> >::iterator i =
	   CurrentIFRs->begin(); i != CurrentIFRs->end(); i++) {
      Value *V = i->first;
      IFRType T = i->second->first;
      InstructionSet &Accesses = i->second->second;

      *OutputFile << "{ ";

      *OutputFile << "ID = " << id << ", ";

      *OutputFile << "Module = \"" << I->getParent()->getParent()->getParent()->getModuleIdentifier() << "\", ";

      *OutputFile << "Type = \""
		  << (T == MayWriteIFR ?
		      "MAY" : "MUST")
		  << "\", ";

      *OutputFile << "Begin = \"" << (Start ? "START" : "CONTINUE") << "\", ";

      *OutputFile << "Placement = \"";
      switch (Placement) {
      case IFRCallPlacement:
	*OutputFile << "CALL";
	break;
      case IFRBBPlacement:
	*OutputFile << "BB";
	break;
      case IFRDeclPlacement:
	*OutputFile << "DECL";
	break;
      case IFRReleasePlacement:
	*OutputFile << "RELEASE";
	break;
      default:
	break;
      }
      *OutputFile << "\", ";

      *OutputFile << "Where = \"" << (Before ? "BEFORE" : "AFTER") << "\", ";

      if (MDNode *N = I->getMetadata("dbg")) {
	DILocation Loc(N);
	*OutputFile << "File = \"" << Loc.getFilename() << "\", ";
	*OutputFile << "Line = " << Loc.getLineNumber() << ", ";
      }

      if (V->hasName()) {
	*OutputFile << "Var = \"" << V->getName() << "\", ";
      }

      if ((Placement == IFRCallPlacement || Placement == IFRReleasePlacement)) {
	if (CallInst *CI = dyn_cast<CallInst>(I)) {
	  if (CI->getCalledFunction()
	      && CI->getCalledFunction()->hasName()) {
	    *OutputFile << "At = \"" << CI->getCalledFunction()->getName() << "\", ";
	  }
	}
      }

      *OutputFile << "Accesses = {";
      InstructionSet::iterator ii = Accesses.begin();
      if (MDNode *N = (*ii)->getMetadata("dbg")) {
	DILocation Loc(N);
	*OutputFile << Loc.getFilename() << ":";
	*OutputFile << Loc.getLineNumber();
      }
      for (ii++; ii != Accesses.end(); ii++) {
	if (MDNode *N = (*ii)->getMetadata("dbg")) {
	  DILocation Loc(N);
	  *OutputFile << ", " << Loc.getFilename() << ":";
	  *OutputFile << Loc.getLineNumber();
	}
      }

      *OutputFile << "} }\n";
    }
  } else {
    *OutputFile << "{ ";

    *OutputFile << "ID = " << id << ", ";

    *OutputFile << "Module = \"" << I->getParent()->getParent()->getParent()->getModuleIdentifier() << "\", ";

    *OutputFile << "Type = \"NONE\", ";

    *OutputFile << "Begin = \"STOP\", ";

    *OutputFile << "Placement = \"";
    switch (Placement) {
    case IFRCallPlacement:
      *OutputFile << "CALL";
      break;
    case IFRBBPlacement:
      *OutputFile << "BB";
      break;
    case IFRDeclPlacement:
      *OutputFile << "DECL";
      break;
    case IFRReleasePlacement:
      *OutputFile << "RELEASE";
      break;
    default:
      break;
    }
    *OutputFile << "\", ";

    *OutputFile << "Where = \"" << (Before ? "BEFORE" : "AFTER") << "\", ";

    if (MDNode *N = I->getMetadata("dbg")) {
      DILocation Loc(N);
      *OutputFile << "File = \"" << Loc.getFilename() << "\", ";
      *OutputFile << "Line = " << Loc.getLineNumber() << ", ";
    }

    if ((Placement == IFRCallPlacement || Placement == IFRReleasePlacement)) {
      if (CallInst *CI = dyn_cast<CallInst>(I)) {
	if (CI->getCalledFunction()
	    && CI->getCalledFunction()->hasName()) {
	  *OutputFile << "At = \"" << CI->getCalledFunction()->getName() << "\", ";
	}
      }
    }

    *OutputFile << "} }\n";
  }
}

void InsertDRDCalls::instrumentReleaseAcquireCalls
(Module &M, std::string Name) {
  Function *Old = M.getFunction(Name);
  if (Old) {
    // Construct new function name, e.g. "___pthread_mutex_lock".
    std::string NewName = "IFRit_" + Name;

    // Construct a new function type from the type of the old function.
    FunctionType *NewType = constructNewFunctionType(Old, false);

    // Insert a declaration of the custom function.
    Function *New = cast<Function>
      (M.getOrInsertFunction(NewName, NewType, Old->getAttributes()));
    //std::cerr << "Inserted function: " << NewName << std::endl;

    // Set the calling convention
    New->setCallingConv(CallingConv::C);

    // Replace all calls to pthread_lock with the new functions.
    replaceAllCalls(M, Old, New, false);
  }
}

void InsertDRDCalls::instrumentOtherCalls
(Module &M, std::string Name) {
  Function *Old = M.getFunction(Name);
  if (Old) {
    // Construct new function name, e.g. "___pthread_mutex_lock".
    std::string NewName = "IFRit_" + Name;

    // Construct a new function type from the type of the old function.
    FunctionType *NewType = constructNewFunctionType(Old, false);

    // Insert a declaration of the custom function.
    Function *New = cast<Function>
      (M.getOrInsertFunction(NewName, NewType, Old->getAttributes()));
    //std::cerr << "Inserted function: " << NewName << std::endl;

    // Set the calling convention
    New->setCallingConv(CallingConv::C);

    // Replace all calls to pthread_lock with the new functions.
    replaceAllCalls(M, Old, New, false);
  }
}

void InsertDRDCalls::insertEndIFRCalls
(Module &M, std::string Name) {
  Function *F = M.getFunction(Name);
  if (F == NULL) return;

  Function *EndIFRs = createEndIFRsFunction(M);

  // Replace calls to the old function with a calls to the new
  // function.
  for (Value::use_iterator i = F->use_begin(),
	 e = F->use_end(); i != e; ++i) {
    CallSite CS(cast<Value>(*i));
    if (CS && CS.getCalledFunction() == F) {
      std::vector<Value *> Args;
      unsigned int id = counter++;

//       // Check to see if there are any IFRs for this call.
//       std::map<CallInst *, IFRs>::iterator ii
// 	= ReleaseIFRs.end();
//       if (CS.isCall()) {
// 	ii = ReleaseIFRs.find(cast<CallInst>(CS.getInstruction()));
//       }
//       if (ii != ReleaseIFRs.end()) {
// 	IFRs *CurrentIFRs = &ii->second;

// 	// For each IFR, pass an extra argument to the function
// 	std::vector<std::pair<Value *,
// 	  IFRInfo *> > MayWriteIFRs;
// 	std::vector<std::pair<Value *,
// 	  IFRInfo *> > MustWriteIFRs;
// 	for(IFRs::iterator iii =
// 	      CurrentIFRs->begin(); iii != CurrentIFRs->end(); iii++) {
// 	  Value *V = iii->first;
// 	  IFRInfo *CurrentInfo = &iii->second;

// 	  if (CurrentInfo->first == MayWriteIFR) {
// 	    MayWriteIFRs.push_back
// 	      (std::pair<Value *, IFRInfo *>
// 	       (V, CurrentInfo));
// 	  } else {
// 	    MustWriteIFRs.push_back
// 	      (std::pair<Value *, IFRInfo *>
// 	       (V, CurrentInfo));
// 	  }
// 	}

// 	// Number of may-write IFRs
// 	ConstantInt *numMayWriteArg = ConstantInt::get
// 	  (M.getContext(), APInt(64, MayWriteIFRs.size()));
// 	Args.push_back(numMayWriteArg);

// 	// Number of must-write IFRs
// 	ConstantInt *numMustWriteArg = ConstantInt::get
// 	  (M.getContext(), APInt(64, MustWriteIFRs.size()));
// 	Args.push_back(numMustWriteArg);

// 	// May-write IFRs
// 	for (std::vector<std::pair<Value *,
// 	       IFRInfo *> >::iterator iii =
// 	       MayWriteIFRs.begin(); iii != MayWriteIFRs.end(); iii++) {
// 	  Args.push_back(iii->first);
// 	}

// 	// Must-write IFRs
// 	for (std::vector<std::pair<Value *,
// 	       IFRInfo *> >::iterator iii =
// 	       MustWriteIFRs.begin(); iii != MustWriteIFRs.end(); iii++) {
// 	  Args.push_back(iii->first);
// 	}

// 	if (MayWriteIFRs.size() || MustWriteIFRs.size()) {
// 	  PrintIFRInfo(id, CS.getInstruction(), &MayWriteIFRs, false, true, IFRReleasePlacement);
// 	  PrintIFRInfo(id, CS.getInstruction(), &MustWriteIFRs, false, true, IFRReleasePlacement);
// 	} else {
// 	  PrintIFRInfo(id, CS.getInstruction(), NULL, false, true, IFRReleasePlacement);
// 	}
//       } else {
	// Replace the call with a call to ___function(..., 0, 0) so
	// that any active IFRs get killed.
// 	ConstantInt *zeroArg = ConstantInt::get(M.getContext(),
// 						  APInt(64, 0));
// 	Args.push_back(zeroArg);
// 	Args.push_back(zeroArg);

	PrintIFRInfo(id, CS.getInstruction(), NULL, false, true, IFRReleasePlacement);
//       }

      CallInst *NewInst = CallInst::Create(EndIFRs, ArrayRef<Value *>(Args),
					   "", CS.getInstruction());
      NewInst->setDoesNotThrow();
      NewInst->setCallingConv(CallingConv::C);

//       NewInst->dump();
    }
  }
}

Function *InsertDRDCalls::createEndIFRsFunction(Module &M) {
  // Construct new function named, "___begin_ifrs".
  std::string NewName = "IFRit_end_ifrs";

  if (Function * F = M.getFunction(NewName)) {
    return F;
  }

  // Construct a new function type from the type of the old function.
  LLVMContext &Context = M.getContext();

  // The return type is void.
  Type *ReturnType = Type::getVoidTy(Context);

  // It takes two int arguments, plus a varargs.
  std::vector<Type *> ParamTypes;

  // ParamTypes.push_back(Type::getInt64Ty(Context));
//   ParamTypes.push_back(Type::getInt64Ty(Context));
//   ParamTypes.push_back(Type::getInt64Ty(Context));

  // The full function type.
  FunctionType *NewType = FunctionType::get
    (ReturnType, ArrayRef<Type *>(ParamTypes), false);

  // Insert a declaration of the custom function.
  Function *NewFunction = cast<Function>
    (M.getOrInsertFunction(NewName, NewType));
  //std::cerr << "Inserted function: " << NewName << std::endl;

  // This function never throws an exceprion.
  NewFunction->setDoesNotThrow();

  // Set the calling convention
  NewFunction->setCallingConv(CallingConv::C);

  return NewFunction;
}

void InsertDRDCalls::trivialInstrumentation(Module &M,
					    Function *BeginReadIFR,
					    Function *BeginWriteIFR) {
  for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
    Function *F = mi;
    for (Function::iterator fi = F->begin(); fi != F->end(); fi++) {
      BasicBlock *B = fi;
      for (BasicBlock::iterator bi = B->begin(); bi != B->end(); bi++) {
	Instruction *I = bi;
	Value *V = NULL;
	Function *BeginIFR = NULL;
	if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
	  V = LI->getPointerOperand();
	  BeginIFR = BeginReadIFR;
	} else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
	  V = SI->getPointerOperand();
	  BeginIFR = BeginWriteIFR;
	}

	if (V) {
	  // Create a cast instruction.
	  BitCastInst *Cast =
	    new BitCastInst(V, Type::getInt64PtrTy(M.getContext()), "", I);

	  // Construct the arguments to begin_ifrs.
	  std::vector<Value *> Args;

	  // IFR ID
	  unsigned int id = counter++;
	  ConstantInt *idArg = ConstantInt::get
	    (M.getContext(), APInt(64, id));
	  Args.push_back(idArg);

	  // Single IFR
	  Args.push_back(Cast);

	  // Create call instruction
	  CallInst *NewInst = CallInst::Create(BeginIFR,
					       ArrayRef<Value *>(Args),
					       "", I);
	  NewInst->setDoesNotThrow();
	  NewInst->setCallingConv(CallingConv::C);
	}
      }
    }
  }
}

#ifdef INSERT_CHECK_IFRS
void InsertDRDCalls::insertCheckIFRs(Module &M) {
  Function *CheckIFR = createCheckIFRFunction(M);
  unsigned long checkCounter = 1;

  for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
    Function *F = mi;
    for (Function::iterator fi = F->begin(); fi != F->end(); fi++) {
      BasicBlock *B = fi;
      for (BasicBlock::iterator bi = B->begin(); bi != B->end(); bi++) {
	Instruction *I = bi;
	Value *V = NULL;
	unsigned int write = 0;
	if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
	  V = LI->getPointerOperand();
	} else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
	  V = SI->getPointerOperand();
	  write = 1;
	}

	if (V) {
	  // Create a cast instruction.
	  BitCastInst *Cast =
	    new BitCastInst(V, Type::getInt64PtrTy(M.getContext()), "", I);

	  // Construct the arguments to begin_ifrs.
	  std::vector<Value *> Args;

	  // ID arg
	  ConstantInt *idArg = ConstantInt::get
	    (M.getContext(), APInt(64, checkCounter++));
	  Args.push_back(idArg);

	  // pointer arg
	  Args.push_back(Cast);

	  // is_write arg
	  ConstantInt *writeArg = ConstantInt::get
	    (M.getContext(), APInt(64, write));
	  Args.push_back(writeArg);

	  // Create call instruction
	  CallInst *NewInst = CallInst::Create(CheckIFR,
					       ArrayRef<Value *>(Args),
					       "", I);
	  NewInst->setDoesNotThrow();
	  NewInst->setCallingConv(CallingConv::C);
	}
      }
    }
  }
}
#endif
