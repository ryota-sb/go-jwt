package myerror

type BadRequestError struct {
	Err error
}

func (e *BadRequestError) Error() string {
	return "Bad Request Error"
}

type InternalServerError struct {
	Err error
}

func (e *InternalServerError) Error() string {
	return "Internal Server Error"
}