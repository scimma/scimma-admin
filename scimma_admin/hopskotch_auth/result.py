from typing import Any, Callable, Generic, Optional, TypeVar, overload

T = TypeVar('T')
E = TypeVar('E')

class Result(Generic[T,E]):
    def __init__(self, value: T, error: Optional[E]):
        # there should not be both a success value and an error value set
        assert not (value is not None and error is not None)
        self.value: T = value
        self.error: Optional[E] = error

    def is_ok(self) -> bool:
        return self.error is None

    def is_error(self) -> bool:
        return self.error is not None

    def ok(self) -> T:
        assert self.error is None
        return self.value

    def err(self) -> E:
        assert self.error is not None
        return self.error

    def and_then(self, op: Callable[[T], Any]) -> Any:
        if self.is_error():
            return self
        return op(self.ok())

    def __str__(self) -> str:
        if self.is_ok():
            return str(self.value)
        return f"Error: {self.error}"

    def __bool__(self) -> bool:
        return self.is_ok()

class Ok(Result[T, Any]):
    def __init__(self, value: T) -> None:
        # the success value _may_ be None
        Result.__init__(self, value=value, error=None)

class Err(Result[Any, E]):
    def __init__(self, error: E):
        # some error value is required
        assert error is not None
        Result.__init__(self, value=None, error=error)
