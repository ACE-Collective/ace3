import os
import subprocess
from pathlib import Path

import pytest

from saq.configuration import get_config
from saq.configuration.schema import GitRepoConfig
from saq.git import (
    GitRepo,
    get_configured_repos,
)


@pytest.mark.unit
class TestGitRepo:
    def test_gitrepo_creation(self):
        repo = GitRepo(config=GitRepoConfig(
            name="repo",
            description="repo",
            local_path="/path/to/repo",
            git_url="https://github.com/user/repo.git",
            update_frequency=3600,
            branch="main"
        ))
        
        assert repo.config.local_path == "/path/to/repo"
        assert repo.config.git_url == "https://github.com/user/repo.git"
        assert repo.config.update_frequency == 3600
        assert repo.config.branch == "main"

    def test_gitrepo_dataclass_equality(self):
        repo1 = GitRepo(config=GitRepoConfig(
            name="repo1",
            description="repo1",
            local_path="/path/to/repo",
            git_url="https://github.com/user/repo.git",
            update_frequency=3600,
            branch="main"
        ))
        
        repo2 = GitRepo(config=GitRepoConfig(
            name="repo1",
            description="repo1",
            local_path="/path/to/repo",
            git_url="https://github.com/user/repo.git",
            update_frequency=3600,
            branch="main"
        ))
        
        assert repo1 == repo2

    def test_gitrepo_dataclass_inequality(self):
        repo1 = GitRepo(config=GitRepoConfig(
            name="repo1",
            description="repo1",
            local_path="/path/to/repo1",
            git_url="https://github.com/user/repo1.git",
            update_frequency=3600,
            branch="main"
        ))
        
        repo2 = GitRepo(config=GitRepoConfig(
            name="repo2",
            description="repo2",
            local_path="/path/to/repo2",
            git_url="https://github.com/user/repo2.git",
            update_frequency=7200,
            branch="develop"
        ))
        
        assert repo1 != repo2


@pytest.mark.unit
class TestRepoExists:
    def test_repo_exists_true(self, tmpdir):
        repo_path = tmpdir.mkdir("test_repo")
        git_dir = repo_path.mkdir(".git")

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=str(repo_path),
            git_url="dummy",
            update_frequency=3600,
            branch="main"
        ))

        assert repo.clone_exists() is True

    def test_repo_exists_false_no_git_dir(self, tmpdir):
        repo_path = tmpdir.mkdir("not_a_repo")

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=str(repo_path),
            git_url="dummy",
            update_frequency=3600,
            branch="main"
        ))

        assert repo.clone_exists() is False

    def test_repo_exists_false_nonexistent_path(self, tmpdir):
        nonexistent_path = str(tmpdir.join("nonexistent"))

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=nonexistent_path,
            git_url="dummy",
            update_frequency=3600,
            branch="main"
        ))

        assert repo.clone_exists() is False


@pytest.mark.integration
class TestGetRepoBranch:
    def setup_test_repo(self, tmpdir):
        repo_path = tmpdir.mkdir("test_repo")
        subprocess.run(["git", "init"], cwd=str(repo_path), check=True)
        
        test_file = repo_path.join("test.txt")
        test_file.write("initial content")
        
        subprocess.run(["git", "add", "test.txt"], cwd=str(repo_path), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Initial commit"], cwd=str(repo_path), check=True)
        
        return str(repo_path)

    def test_get_repo_branch_main(self, tmpdir):
        repo_path = self.setup_test_repo(tmpdir)
        subprocess.run(["git", "checkout", "-b", "main"], cwd=repo_path, check=True)

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=repo_path,
            git_url="dummy",
            update_frequency=3600,
            branch="main"
        ))

        branch = repo.get_repo_branch()

        assert branch == "main"

    def test_get_repo_branch_develop(self, tmpdir):
        repo_path = self.setup_test_repo(tmpdir)
        subprocess.run(["git", "checkout", "-b", "develop"], cwd=repo_path, check=True)

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=repo_path,
            git_url="dummy",
            update_frequency=3600,
            branch="develop"
        ))

        branch = repo.get_repo_branch()

        assert branch == "develop"

    def test_get_repo_branch_master_default(self, tmpdir):
        repo_path = self.setup_test_repo(tmpdir)

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=repo_path,
            git_url="dummy",
            update_frequency=3600,
            branch="master"
        ))

        branch = repo.get_repo_branch()

        assert branch in ["master", "main"]

    def test_get_repo_branch_nonexistent_repo(self, tmpdir):
        nonexistent_path = str(tmpdir.join("nonexistent"))

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=nonexistent_path,
            git_url="dummy",
            update_frequency=3600,
            branch="master"
        ))

        with pytest.raises(RuntimeError, match="repo .* does not exist"):
            repo.get_repo_branch()

    def test_get_repo_branch_invalid_repo(self, tmpdir):
        not_a_repo = tmpdir.mkdir("not_a_repo")

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=str(not_a_repo),
            git_url="dummy",
            update_frequency=3600,
            branch="master"
        ))

        with pytest.raises(RuntimeError, match="repo .* does not exist"):
            repo.get_repo_branch()


@pytest.mark.integration
class TestCloneRepo:
    def setup_remote_repo(self, tmpdir):
        remote_path = tmpdir.mkdir("remote_repo")
        
        subprocess.run(["git", "init", "--bare"], cwd=str(remote_path), check=True)
        
        temp_clone = tmpdir.mkdir("temp_clone")
        subprocess.run(["git", "clone", str(remote_path), str(temp_clone)], check=True)
        
        test_file = temp_clone.join("test.txt")
        test_file.write("test content")
        
        subprocess.run(["git", "add", "test.txt"], cwd=str(temp_clone), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Initial commit"], cwd=str(temp_clone), check=True)
        subprocess.run(["git", "push", "origin", "master"], cwd=str(temp_clone), check=True)
        
        subprocess.run(["git", "checkout", "-b", "test-branch"], cwd=str(temp_clone), check=True)
        branch_file = temp_clone.join("branch.txt")
        branch_file.write("branch content")
        subprocess.run(["git", "add", "branch.txt"], cwd=str(temp_clone), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Branch commit"], cwd=str(temp_clone), check=True)
        subprocess.run(["git", "push", "origin", "test-branch"], cwd=str(temp_clone), check=True)
        
        return str(remote_path)

    def test_clone_repo_success_default_branch(self, tmpdir):
        remote_path = self.setup_remote_repo(tmpdir)
        local_path = str(tmpdir.join("cloned_repo"))

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=local_path,
            git_url=remote_path,
            update_frequency=3600,
            branch="master"
        ))

        result = repo.clone_repo()

        assert result is True
        assert os.path.exists(local_path)
        assert os.path.exists(os.path.join(local_path, ".git"))
        assert os.path.exists(os.path.join(local_path, "test.txt"))

    def test_clone_repo_success_specific_branch(self, tmpdir):
        remote_path = self.setup_remote_repo(tmpdir)
        local_path = str(tmpdir.join("cloned_repo"))

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=local_path,
            git_url=remote_path,
            update_frequency=3600,
            branch="test-branch"
        ))

        result = repo.clone_repo()

        assert result is True
        assert os.path.exists(local_path)
        assert os.path.exists(os.path.join(local_path, ".git"))
        assert os.path.exists(os.path.join(local_path, "branch.txt"))

    def test_clone_repo_failure_invalid_url(self, tmpdir):
        local_path = str(tmpdir.join("cloned_repo"))
        invalid_url = "https://invalid-url-that-does-not-exist.com/repo.git"

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=local_path,
            git_url=invalid_url,
            update_frequency=3600,
            branch="main"
        ))

        with pytest.raises(RuntimeError, match="failed to clone repo"):
            repo.clone_repo()

    def test_clone_repo_failure_invalid_branch(self, tmpdir):
        remote_path = self.setup_remote_repo(tmpdir)
        local_path = str(tmpdir.join("cloned_repo"))

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=local_path,
            git_url=remote_path,
            update_frequency=3600,
            branch="nonexistent-branch"
        ))

        with pytest.raises(RuntimeError, match="failed to clone repo"):
            repo.clone_repo()


@pytest.mark.integration
class TestChangeRepoBranch:
    def setup_multi_branch_repo(self, tmpdir):
        repo_path = tmpdir.mkdir("test_repo")
        subprocess.run(["git", "init"], cwd=str(repo_path), check=True)
        
        test_file = repo_path.join("test.txt")
        test_file.write("initial content")
        subprocess.run(["git", "add", "test.txt"], cwd=str(repo_path), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Initial commit"], cwd=str(repo_path), check=True)
        
        subprocess.run(["git", "checkout", "-b", "develop"], cwd=str(repo_path), check=True)
        dev_file = repo_path.join("dev.txt")
        dev_file.write("dev content")
        subprocess.run(["git", "add", "dev.txt"], cwd=str(repo_path), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Dev commit"], cwd=str(repo_path), check=True)
        
        subprocess.run(["git", "checkout", "master"], cwd=str(repo_path), check=True)
        
        return str(repo_path)

    def test_change_repo_branch_success(self, tmpdir):
        repo_path = self.setup_multi_branch_repo(tmpdir)

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=repo_path,
            git_url="dummy",
            update_frequency=3600,
            branch="master"
        ))

        assert repo.get_repo_branch() == "master"

        result = repo.change_repo_branch("develop")

        assert result is True
        assert repo.get_repo_branch() == "develop"
        assert os.path.exists(os.path.join(repo_path, "dev.txt"))

    def test_change_repo_branch_same_branch(self, tmpdir):
        repo_path = self.setup_multi_branch_repo(tmpdir)

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=repo_path,
            git_url="dummy",
            update_frequency=3600,
            branch="master"
        ))

        assert repo.get_repo_branch() == "master"

        result = repo.change_repo_branch("master")

        assert result is True
        assert repo.get_repo_branch() == "master"

    def test_change_repo_branch_nonexistent_branch(self, tmpdir):
        repo_path = self.setup_multi_branch_repo(tmpdir)

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=repo_path,
            git_url="dummy",
            update_frequency=3600,
            branch="master"
        ))

        with pytest.raises(RuntimeError, match="failed to change branch"):
            repo.change_repo_branch("nonexistent-branch")

    def test_change_repo_branch_nonexistent_repo(self, tmpdir):
        nonexistent_path = str(tmpdir.join("nonexistent"))

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=nonexistent_path,
            git_url="dummy",
            update_frequency=3600,
            branch="master"
        ))

        with pytest.raises(RuntimeError, match="repo .* does not exist"):
            repo.change_repo_branch("main")

    def test_change_repo_branch_invalid_repo(self, tmpdir):
        not_a_repo = tmpdir.mkdir("not_a_repo")

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=str(not_a_repo),
            git_url="dummy",
            update_frequency=3600,
            branch="master"
        ))

        with pytest.raises(RuntimeError, match="repo .* does not exist"):
            repo.change_repo_branch("main")

    def test_change_repo_branch_remote_tracking(self, tmpdir):
        repo_path = self.setup_multi_branch_repo(tmpdir)

        subprocess.run(["git", "checkout", "-b", "feature"], cwd=repo_path, check=True)
        feature_file = Path(repo_path) / "feature.txt"
        feature_file.write_text("feature content")
        subprocess.run(["git", "add", "feature.txt"], cwd=repo_path, check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Feature commit"], cwd=repo_path, check=True)

        subprocess.run(["git", "checkout", "master"], cwd=repo_path, check=True)

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=repo_path,
            git_url="dummy",
            update_frequency=3600,
            branch="feature"
        ))

        result = repo.change_repo_branch("feature")

        assert result is True
        assert repo.get_repo_branch() == "feature"
        assert os.path.exists(os.path.join(repo_path, "feature.txt"))


@pytest.mark.integration
class TestRepoIsUpToDate:
    def setup_test_repo(self, tmpdir):
        repo_path = tmpdir.mkdir("test_repo")
        subprocess.run(["git", "init"], cwd=str(repo_path), check=True)
        
        test_file = repo_path.join("test.txt")
        test_file.write("initial content")
        
        subprocess.run(["git", "add", "test.txt"], cwd=str(repo_path), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Initial commit"], cwd=str(repo_path), check=True)
        
        return str(repo_path)

    def test_repo_is_up_to_date_clean_working_tree(self, tmpdir):
        repo_path = self.setup_test_repo(tmpdir)

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=repo_path,
            git_url="dummy_url",
            update_frequency=3600,
            branch="master"
        ))

        result = repo.repo_is_up_to_date()

        assert result is True

    def test_repo_is_up_to_date_dirty_working_tree(self, tmpdir):
        repo_path = self.setup_test_repo(tmpdir)

        test_file = Path(repo_path) / "test.txt"
        test_file.write_text("modified content")

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=repo_path,
            git_url="dummy_url",
            update_frequency=3600,
            branch="master"
        ))

        result = repo.repo_is_up_to_date()

        assert result is False

    def test_repo_is_up_to_date_untracked_files(self, tmpdir):
        repo_path = self.setup_test_repo(tmpdir)

        new_file = Path(repo_path) / "new.txt"
        new_file.write_text("new content")

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=repo_path,
            git_url="dummy_url",
            update_frequency=3600,
            branch="master"
        ))

        result = repo.repo_is_up_to_date()

        assert result is False

    def test_repo_is_up_to_date_staged_changes(self, tmpdir):
        repo_path = self.setup_test_repo(tmpdir)

        new_file = Path(repo_path) / "staged.txt"
        new_file.write_text("staged content")
        subprocess.run(["git", "add", "staged.txt"], cwd=repo_path, check=True)

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=repo_path,
            git_url="dummy_url",
            update_frequency=3600,
            branch="master"
        ))

        result = repo.repo_is_up_to_date()

        assert result is False

    def test_repo_is_up_to_date_invalid_repo_path(self, tmpdir):
        invalid_path = str(tmpdir.join("nonexistent"))

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=invalid_path,
            git_url="dummy_url",
            update_frequency=3600,
            branch="master"
        ))

        assert not repo.repo_is_up_to_date()

    def test_repo_is_up_to_date_remote_ahead(self, tmpdir):
        # setup remote repo
        remote_path = tmpdir.mkdir("remote_repo")
        subprocess.run(["git", "init", "--bare"], cwd=str(remote_path), check=True)
        
        # setup initial repo and push
        temp_setup = tmpdir.mkdir("temp_setup")
        subprocess.run(["git", "clone", str(remote_path), str(temp_setup)], check=True)
        
        test_file = temp_setup.join("test.txt")
        test_file.write("initial content")
        subprocess.run(["git", "add", "test.txt"], cwd=str(temp_setup), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Initial commit"], cwd=str(temp_setup), check=True)
        subprocess.run(["git", "push", "origin", "master"], cwd=str(temp_setup), check=True)
        
        # clone to local repo
        local_path = str(tmpdir.join("local_repo"))
        subprocess.run(["git", "clone", str(remote_path), local_path], check=True)
        
        # add new commit to remote
        new_file = temp_setup.join("new.txt")
        new_file.write("new content")
        subprocess.run(["git", "add", "new.txt"], cwd=str(temp_setup), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "New commit"], cwd=str(temp_setup), check=True)
        subprocess.run(["git", "push", "origin", "master"], cwd=str(temp_setup), check=True)
        
        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=local_path,
            git_url=str(remote_path),
            update_frequency=3600,
            branch="master"
        ))

        # local repo should not be up to date since remote has new commits
        result = repo.repo_is_up_to_date()
        assert result is False


@pytest.mark.integration
class TestPullRepo:
    def setup_remote_and_local_repos(self, tmpdir):
        remote_path = tmpdir.mkdir("remote_repo")
        subprocess.run(["git", "init", "--bare"], cwd=str(remote_path), check=True)
        
        temp_setup = tmpdir.mkdir("temp_setup")
        subprocess.run(["git", "clone", str(remote_path), str(temp_setup)], check=True)
        
        test_file = temp_setup.join("test.txt")
        test_file.write("initial content")
        subprocess.run(["git", "add", "test.txt"], cwd=str(temp_setup), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Initial commit"], cwd=str(temp_setup), check=True)
        subprocess.run(["git", "push", "origin", "master"], cwd=str(temp_setup), check=True)
        
        local_path = tmpdir.mkdir("local_repo")
        subprocess.run(["git", "clone", str(remote_path), str(local_path)], check=True)
        
        test_file.write("updated content")
        subprocess.run(["git", "add", "test.txt"], cwd=str(temp_setup), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Update commit"], cwd=str(temp_setup), check=True)
        subprocess.run(["git", "push", "origin", "master"], cwd=str(temp_setup), check=True)
        
        return str(remote_path), str(local_path)

    def test_pull_repo_success(self, tmpdir):
        remote_path, local_path = self.setup_remote_and_local_repos(tmpdir)

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=local_path,
            git_url=remote_path,
            update_frequency=3600,
            branch="master"
        ))

        result = repo.pull_repo()

        assert result is True

        test_file_content = Path(local_path) / "test.txt"
        assert test_file_content.read_text() == "updated content"

    def test_pull_repo_failure_invalid_repo_path(self, tmpdir):
        invalid_path = str(tmpdir.join("nonexistent"))

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=invalid_path,
            git_url="dummy_url",
            update_frequency=3600,
            branch="master"
        ))

        with pytest.raises(RuntimeError, match="failed to pull latest changes"):
            repo.pull_repo()

    def test_pull_repo_failure_invalid_remote(self, tmpdir):
        repo_path = tmpdir.mkdir("test_repo")
        subprocess.run(["git", "init"], cwd=str(repo_path), check=True)

        repo = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=str(repo_path),
            git_url="https://invalid-remote.com/repo.git",
            update_frequency=3600,
            branch="master"
        ))

        with pytest.raises(RuntimeError, match="failed to pull latest changes"):
            repo.pull_repo()


@pytest.mark.integration
class TestUpdateRepo:
    def setup_remote_repo(self, tmpdir):
        remote_path = tmpdir.mkdir("remote_repo")
        subprocess.run(["git", "init", "--bare"], cwd=str(remote_path), check=True)
        
        temp_setup = tmpdir.mkdir("temp_setup")
        subprocess.run(["git", "clone", str(remote_path), str(temp_setup)], check=True)
        
        test_file = temp_setup.join("test.txt")
        test_file.write("initial content")
        subprocess.run(["git", "add", "test.txt"], cwd=str(temp_setup), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Initial commit"], cwd=str(temp_setup), check=True)
        subprocess.run(["git", "push", "origin", "master"], cwd=str(temp_setup), check=True)
        
        return str(remote_path)

    def test_update_repo_clone_new_repo(self, tmpdir):
        remote_path = self.setup_remote_repo(tmpdir)
        local_path = str(tmpdir.join("new_repo"))
        
        repo = GitRepo(config=GitRepoConfig(
            name="repo",
            description="repo",
            local_path=local_path,
            git_url=remote_path,
            update_frequency=3600,
            branch="master"
        ))
        
        result = repo.update()
        
        assert result is True
        assert os.path.exists(local_path)
        assert os.path.exists(os.path.join(local_path, ".git"))
        assert os.path.exists(os.path.join(local_path, "test.txt"))

    def test_update_repo_creates_directory(self, tmpdir):
        remote_path = self.setup_remote_repo(tmpdir)
        local_path = str(tmpdir.join("nested", "path", "repo"))
        
        repo = GitRepo(config=GitRepoConfig(
            name="repo",
            description="repo",
            local_path=local_path,
            git_url=remote_path,
            update_frequency=3600,
            branch="master"
        ))
        
        result = repo.update()
        
        assert result is True
        assert os.path.exists(local_path)
        assert os.path.exists(os.path.join(local_path, ".git"))

    def test_update_repo_up_to_date_repo(self, tmpdir):
        remote_path = self.setup_remote_repo(tmpdir)
        local_path = str(tmpdir.join("existing_repo"))
        
        subprocess.run(["git", "clone", remote_path, local_path], check=True)
        
        repo = GitRepo(config=GitRepoConfig(
            name="repo",
            description="repo",
            local_path=local_path,
            git_url=remote_path,
            update_frequency=3600,
            branch="master"
        ))
        
        result = repo.update()
        
        assert result is False

    def test_update_repo_pull_updates(self, tmpdir):
        remote_path = self.setup_remote_repo(tmpdir)
        local_path = str(tmpdir.join("existing_repo"))
        
        subprocess.run(["git", "clone", remote_path, local_path], check=True)
        
        temp_update = tmpdir.mkdir("temp_update")
        subprocess.run(["git", "clone", remote_path, str(temp_update)], check=True)
        
        update_file = temp_update.join("update.txt")
        update_file.write("updated content")
        subprocess.run(["git", "add", "update.txt"], cwd=str(temp_update), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Update commit"], cwd=str(temp_update), check=True)
        subprocess.run(["git", "push", "origin", "master"], cwd=str(temp_update), check=True)
        
        local_file = Path(local_path) / "local_change.txt"
        local_file.write_text("local change")
        
        repo = GitRepo(config=GitRepoConfig(
            name="repo",
            description="repo",
            local_path=local_path,
            git_url=remote_path,
            update_frequency=3600,
            branch="master"
        ))
        
        result = repo.update()
        
        assert result is True
        assert os.path.exists(os.path.join(local_path, "update.txt"))

    def test_update_repo_switches_branch(self, tmpdir):
        remote_path = self.setup_remote_repo(tmpdir)
        local_path = str(tmpdir.join("existing_repo"))
        
        subprocess.run(["git", "clone", remote_path, local_path], check=True)
        
        temp_update = tmpdir.mkdir("temp_update")
        subprocess.run(["git", "clone", remote_path, str(temp_update)], check=True)
        
        subprocess.run(["git", "checkout", "-b", "develop"], cwd=str(temp_update), check=True)
        dev_file = temp_update.join("develop.txt")
        dev_file.write("develop content")
        subprocess.run(["git", "add", "develop.txt"], cwd=str(temp_update), check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "Develop commit"], cwd=str(temp_update), check=True)
        subprocess.run(["git", "push", "origin", "develop"], cwd=str(temp_update), check=True)
        
        subprocess.run(["git", "fetch", "origin", "develop"], cwd=local_path, check=True)
        
        repo_for_check = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=local_path,
            git_url="dummy",
            update_frequency=3600,
            branch="master"
        ))
        assert repo_for_check.get_repo_branch() == "master"
        
        repo = GitRepo(config=GitRepoConfig(
            name="repo",
            description="repo",
            local_path=local_path,
            git_url=remote_path,
            update_frequency=3600,
            branch="develop"
        ))
        
        result = repo.update()
        
        repo_for_check = GitRepo(config=GitRepoConfig(
            name="test",
            description="test",
            local_path=local_path,
            git_url="dummy",
            update_frequency=3600,
            branch="develop"
        ))
        assert repo_for_check.get_repo_branch() == "develop"
        assert os.path.exists(os.path.join(local_path, "develop.txt"))


@pytest.mark.unit
class TestGetConfiguredRepos:
    def test_get_configured_repos_mock_config(self, monkeypatch):
        get_config().clear_git_repo_configs()
        get_config().add_git_repo_config("repo1", GitRepoConfig(
            name="repo1",
            description="Test repo 1",
            local_path="/path/to/repo1",
            git_url="https://github.com/user/repo1.git",
            update_frequency=3600,
            branch="main"
        ))
        get_config().add_git_repo_config("repo2", GitRepoConfig(
            name="repo2",
            description="Test repo 2",
            local_path="/path/to/repo2",
            git_url="https://github.com/user/repo2.git",
            update_frequency=7200,
            branch="develop"
        ))
        
        repos = get_configured_repos()
        
        assert len(repos) == 2
        
        assert repos[0].config.name == "repo1"
        assert repos[0].config.description == "Test repo 1"
        assert repos[0].config.local_path == "/path/to/repo1"
        assert repos[0].config.git_url == "https://github.com/user/repo1.git"
        assert repos[0].config.update_frequency == 3600
        assert repos[0].config.branch == "main"

        assert repos[1].config.name == "repo2"
        assert repos[1].config.description == "Test repo 2"
        assert repos[1].config.local_path == "/path/to/repo2"
        assert repos[1].config.git_url == "https://github.com/user/repo2.git"
        assert repos[1].config.update_frequency == 7200
        assert repos[1].config.branch == "develop"

    def test_get_configured_repos_empty_config(self, monkeypatch):
        get_config().clear_git_repo_configs()
        repos = get_configured_repos()
        assert len(repos) == 0
