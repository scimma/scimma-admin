from django.core.management import BaseCommand
import git
import os
from scimma_admin.settings import BASE_DIR, HAVE_WEBSITE

class Command(BaseCommand):
    help = "Fetch any updates to the website application"

    def update_home(self) -> int:
        if not HAVE_WEBSITE:
            self.stdout.write("Website app not present; skipping update")
            return 0
        
        app_dir = os.path.join(BASE_DIR, "home")
        app_src = os.readlink(app_dir)
        if not os.path.isabs(app_src):
            app_src = os.path.join(os.path.dirname(app_dir), app_src)
            
        git_dir = app_src
        while True:
            try:
                os.stat(os.path.join(git_dir, ".git"))
                break
            except FileNotFoundError:
                parent_dir = os.path.dirname(git_dir)
                if parent_dir == git_dir:
                    self.stderr.write(f"Could not find git metadata in {app_src} or any parent directory")
                    return 1
                git_dir = parent_dir
        r = git.repo.Repo(git_dir)
        orig_commit = r.commit()
        try:
            origin = r.remote("origin")
        except ValueError:
            self.stderr.write(f"Repository has no 'origin' remote")
            return 1
        origin.pull()
        current_commit = r.commit()
        if current_commit != orig_commit:
            self.stdout.write(f"Now at commit {current_commit}")
            try:
                manage_script = os.path.join(BASE_DIR, "manage.py")
                os.stat(manage_script)
                self.stdout.write(f"Re-collecting static assets")
                os.system(f"python {manage_script} collectstatic --noinput")
            except Exception as ex:
                self.stderr.write(f"Failed to re-collect static assets: {ex}")
            pid_path = "/tmp/project-master.pid"
            try:
                os.stat(pid_path)
                self.stdout.write(f"Asking uwsgi to reload")
                os.system(f"uwsgi --reload {pid_path}")
            except FileNotFoundError:
                self.stderr.write(f"{pid_path} does not exist; do not know how to reload uwsgi")
                return 1
        return 0

    def handle(self, *args, **options):
        self.update_home()