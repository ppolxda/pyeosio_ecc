class SignBaseError(Exception):
    pass


class PubKeyError(SignBaseError):
    pass


class SignatureInvaild(SignBaseError):
    pass


class InputInvaild(SignBaseError):
    pass
 