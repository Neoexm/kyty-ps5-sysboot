void TestInitialModuleStageStackContract() {
  const char* test = "InitialModuleStageStackContract";
  Check(test, Loader::TestInitialModuleStageUsesGuestStack(),
        "module initializer locals must use owned guest memory without admitting host stack pointers");
  std::printf("[host]    %-48s ok\n", test);
}
