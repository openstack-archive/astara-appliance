from akanda.router import utils


class Manager(object):
    def __init__(self, root_helper='sudo'):
        self.root_helper = root_helper

    def sudo(self, *args):
        return utils.execute([self.EXECUTABLE] + list(args), self.root_helper)

    def do(self, *args):
        return utils.execute([self.EXECUTABLE] + list(args))
