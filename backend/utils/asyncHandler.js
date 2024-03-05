const asyncHandler = (requestFunction) => {
    return (req, res, next) => {
        Promise.resolve(requestFunction(req, res, next))
        .catch((error) => {
            return next(error);
        })
    }
}

export { asyncHandler }