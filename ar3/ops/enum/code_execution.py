class ExecutionTimeout():
    def __init__(self, exec_obj, command):
        self.result = "Code execution failed: Try \"-M test_execution\" for the best approach"
        self.exec_obj = exec_obj
        self.command = command
        self.running = True

    def execute(self):
        while self.running:
            self.result = self.exec_obj.execute(self.command)
            self.running = False
            return