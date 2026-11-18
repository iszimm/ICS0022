"""Exception types. 'public' is shown to the user, 'detail' only goes to the log."""


class FilemgrError(Exception):
    category = "error"

    def __init__(self, public, detail=""):
        super().__init__(public)
        self.public = public
        self.detail = detail


class AuthError(FilemgrError):
    category = "auth"


class InputError(FilemgrError):
    category = "input"


class PathError(InputError):
    category = "path"


class DecryptError(FilemgrError):
    category = "decrypt"


class AccessDenied(FilemgrError):
    category = "access"
