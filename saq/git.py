import logging
import os
import subprocess
import threading
from typing import Type

from saq.configuration import get_config
from saq.configuration.schema import GitRepoConfig, ServiceConfig
from saq.service import ACEServiceInterface

class GitRepo:
    def __init__(self, config: GitRepoConfig):
        self.config = config

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GitRepo):
            return False

        return self.config == other.config

    @property
    def env(self) -> dict:
        result = {}

        if self.config.ssh_key_path:
            # see https://stackoverflow.com/questions/4565700/how-to-specify-the-private-ssh-key-to-use-when-executing-shell-command-on-git#comment105376577_29754018
            result["GIT_SSH_COMMAND"] = f"ssh -i {self.config.ssh_key_path} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no"

        return result

    def clone_exists(self) -> bool:
        """Returns True if the local repo clone exists at local_path, False otherwise."""
        return os.path.isdir(os.path.join(self.config.local_path, ".git"))

    def _run_git_command(self, args: list[str], error_message: str) -> tuple[str, str]:
        """Runs a git command with timeout and error handling."""
        process = subprocess.Popen(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        try:
            stdout, stderr = process.communicate(timeout=self.config.git_command_timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
        if process.returncode != 0:
            raise RuntimeError(f"{error_message}: {stderr}")
        return stdout, stderr

    def clone_repo(self) -> bool:
        """Clones the repo at the given URL to the given local path and branch."""
        self._run_git_command(
            ["git", "clone", self.config.git_url, self.config.local_path, "--branch", self.config.branch],
            f"failed to clone repo {self.config.git_url} to {self.config.local_path}",
        )
        return True

    def get_repo_branch(self) -> str:
        """Returns the branch of the repo at the given path."""
        if not self.clone_exists():
            raise RuntimeError(f"repo {self.config.local_path} does not exist")

        stdout, _ = self._run_git_command(
            ["git", "-C", self.config.local_path, "rev-parse", "--abbrev-ref", "HEAD"],
            f"failed to get branch of repo {self.config.local_path}",
        )
        return stdout.strip()

    def change_repo_branch(self, branch: str) -> bool:
        """Changes the branch of the repo at the given path."""
        if not self.clone_exists():
            raise RuntimeError(f"repo {self.config.local_path} does not exist")

        self._run_git_command(
            ["git", "-C", self.config.local_path, "checkout", branch],
            f"failed to change branch of repo {self.config.local_path} to {branch}",
        )
        return True

    def repo_is_up_to_date(self) -> bool:
        """Returns True if the repo is up to date, False otherwise."""
        if not self.clone_exists():
            return False

        # fetch remote first
        self._run_git_command(
            ["git", "-C", self.config.local_path, "fetch", "--all"],
            f"failed to fetch remote of repo {self.config.local_path}",
        )

        # check if there are local changes (dirty working tree, staged changes, untracked files)
        stdout, _ = self._run_git_command(
            ["git", "-C", self.config.local_path, "status", "--porcelain"],
            f"failed to check if repo {self.config.local_path} is up to date",
        )

        # if there are local changes, repo is not up to date
        if stdout.strip() != "":
            return False

        # check if local branch is behind remote branch
        remote_branch = f"origin/{self.config.branch}"
        process = subprocess.Popen(
            ["git", "-C", self.config.local_path, "rev-list", "--count", f"HEAD..{remote_branch}"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env,
        )
        try:
            stdout, stderr = process.communicate(timeout=self.config.git_command_timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
        if process.returncode != 0:
            # if remote branch doesn't exist or other error, assume up to date
            return True

        # if there are commits on remote that we don't have locally, we're behind
        commits_behind = int(stdout.strip())
        return commits_behind == 0

    def pull_repo(self) -> bool:
        """Pulls the latest changes from the given URL to the given local path and branch."""
        self._run_git_command(
            ["git", "-C", self.config.local_path, "pull", self.config.git_url, self.config.branch],
            f"failed to pull latest changes from {self.config.git_url} to {self.config.local_path}",
        )
        return True

    def update(self) -> bool:
        """Updates the repo. Returns True if the repo was updated, False otherwise."""
        # ensure the local path exists, create it if not
        if not os.path.isdir(self.config.local_path):
            logging.info(f"creating directory {self.config.local_path}")
            os.makedirs(self.config.local_path)

        # clone the repo if it doesn't exist
        if not self.clone_exists():
            logging.info(f"cloning repo {self.config.git_url} to {self.config.local_path} branch {self.config.branch}")
            return self.clone_repo()
        else:
            if self.get_repo_branch() != self.config.branch:
                logging.info(f"changing branch of repo {self.config.local_path} to {self.config.branch}")
                self.change_repo_branch(self.config.branch)

            logging.info(f"checking if repo {self.config.local_path} is up to date")
            if not self.repo_is_up_to_date():
                logging.info(f"pulling latest changes from {self.config.git_url} to {self.config.local_path} branch {self.config.branch}")
                return self.pull_repo()
            else:
                return False

def get_configured_repos() -> list[GitRepo]:
    result: list[GitRepo] = []
    for git_repo_config in get_config().git_repos:
        result.append(GitRepo(git_repo_config))

    return result

class GitManagerService(ACEServiceInterface):
    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return ServiceConfig

    def __init__(self):
        super().__init__()
        self.started_event = threading.Event()
        self.shutdown_event = threading.Event()
        self.threads: dict[str, threading.Thread] = {}

    def start(self):
        self.started_event.clear()
        self.shutdown_event.clear()
        for repo in get_configured_repos():
            self.start_thread(repo)

        self.started_event.set()
        return True

    def start_thread(self, repo: GitRepo):
        self.threads[repo.config.name] = threading.Thread(target=self.run, args=(repo,))
        self.threads[repo.config.name].daemon = True
        self.threads[repo.config.name].start()

    def run(self, repo: GitRepo):
        while not self.shutdown_event.is_set():
            try:
                repo.update()
            except subprocess.TimeoutExpired:
                logging.warning("git command timed out for repo %s", repo.config.name)
            except Exception:
                logging.error("unexpected error updating repo %s", repo.config.name, exc_info=True)
            self.shutdown_event.wait(repo.config.update_frequency)

    def start_single_threaded(self):
        for repo in get_configured_repos():
            self.run(repo)

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.started_event.wait(timeout)

    def stop(self):
        self.shutdown_event.set()

    def wait(self):
        for repo_name, thread in self.threads.items():
            logging.info(f"waiting for git repo manager thread {repo_name} to finish")
            thread.join()
            logging.info(f"git repo manager thread {repo_name} finished")
    