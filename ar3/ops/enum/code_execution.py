class ExecutionTimeout():
    def __init__(self, exec_obj, command):
        self.result = "Code execution failed: Try \"-M test_execution\" for the best approach"
        self.exec_obj = exec_obj
        self.command = command

    def execute(self):
        try:
            self.result = self.exec_obj.execute(self.command)
        except:
            pass