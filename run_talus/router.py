from utils.router import MainRouter, DbRouter


class TalusRouter(MainRouter, DbRouter):
    def get_choices(self):
        return ['start']

    def route(self, task, action):
        return dict(zip(self.get_choices(), [task.start]))[action]

    @property
    def action(self):
        self.start_db_router()
        return self.get_action()
