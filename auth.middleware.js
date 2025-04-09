const jwt = require('jsonwebtoken')

const authMiddleware = async(req,res,next) => {
    try {
        const token = req.cookies?.token
        const decoded = jwt.verify(token, process.env.JWT_SECRET)
        req.user = decoded
        next()
    } catch (error) {
        console.log(error.messsage)
    }
}

module.exports = authMiddleware