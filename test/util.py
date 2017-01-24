
import tempfile
import shutil

# XXX should move a bunch more stuff in here, but first move this to
# txtorcon/testutil so it's more accessible. also Fakes can go in
# there too.


class TempDir(object):
    '''
    This is a simple context manager that handles creating and
    cleaning up a tempdir.

    See also: https://gist.github.com/meejah/6430613

    '''

    def __enter__(self, *args):
        self.dir_name = tempfile.mkdtemp()
        return self

    def __exit__(self, *args):
        shutil.rmtree(self.dir_name)

    def __str__(self):
        return self.dir_name
