const Joi = require('joi');
const User = require('../models/user');
const bcrypt = require('bcryptjs');
const UserDto = require('../dto/user');
const JWTService = require('../services/JWTService');
const RefreshToken = require('../models/token')

const passwordPattern = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;

const authController = {
    // register route
    async register(req,res,next) {
        // validate user
        const userRegisterSchema = Joi.object({
            username: Joi.string().min(5).max(30).required(),
            name: Joi.string().max(30).required(),
            email: Joi.string().email().required(),
            password: Joi.string().pattern(passwordPattern).required(),
            confirmPassword: Joi.ref('password')
        })

        const {error} = userRegisterSchema.validate(req.body)

        // if error in validation -> return error via middleware

        if(error){
            return next(error)
        }

        // if email or username already exist -> return an error
        const {name,username,email,password} = req.body;

        // if email or username not already exist 

        try {
            const emailInUse = await User.exists({email});
            const usernameInUse = await User.exists({username});

            if(emailInUse){
                const error = {
                    status : 409,
                    message : "Email already exist, use another email",
                }

                return next(error)
            }

            if(usernameInUse){
                const error = {
                    status : 409,
                    message : "Username already exist, use another username",
                }

                return next(error)
            }


        } catch (error) {
            return next(error)
        }

        // password hash
        const hashedPassword = await bcrypt.hash(password, 10);

        // store user data in db

        let accessToken;
        let refreshToken;
        let user;
        try {
            const userToRegister = new User({
                username,
                name,
                email,
                password: hashedPassword
            })
    
             user = await userToRegister.save()

            // token generation
            accessToken = JWTService.signAccessToken({_id: user._id, username: user.username}, '30m');

            refreshToken = JWTService.signRefreshToken({_id: user._id}, '60m');

        } catch (error) {
            return next(error)
        }

        // store refresh token in db
        await JWTService.storeRefreshToken(refreshToken, user._id)
        
        // send token in cookie to db
        res.cookie('accessToken',accessToken, {
            maxAge: 1000 * 60 * 60 *24,
            httpOnly: true 
        })

        res.cookie('refreshToken',refreshToken , {
            maxAge: 1000 * 60 * 60 * 24,
            httpOnly : true
        })
        
        // response send

        const userDto = new UserDto(user)
        return res.status(201).json({user: userDto, auth: true})
    },


    // Login Route

    async login(req, res ,next) {
        // validate user
        const userLoginSchema = Joi.object({
            username: Joi.string().min(5).max(30).required(),
            password: Joi.string().pattern(passwordPattern).required(),
        })

        const {error} = userLoginSchema.validate(req.body)

        // if error then show error via middleware
        if(error){
            return next(error)
        }
        // match username and password in db
        const {username,password} = req.body;
        let user;
        try {
            // match username
            user = await User.findOne({username})

           if(!user){
            const error = {
                status : 401,
                message: 'Invalid username or password'
            }
            return next(error)
           }

        //    match password
        const match = await bcrypt.compare(password, user.password)

        if(!match){
            const error = {
                status: 401,
                message: "Invalid password"
            }
            return next(error)
        }
            
        } catch (error) {
            return next(error)
        }

        let accessToken;
        let refreshToken;

        accessToken = JWTService.signAccessToken({_id: user._id}, '30m')

        refreshToken = JWTService.signRefreshToken({_id: user._id}, '60m')

        // update refresh token in db 
        try {
            await RefreshToken.updateOne({
                _id: user._id,
            },
            {token: refreshToken},
            {upsert: true}
        )
        } catch (error) {
            return next(error)
        }
        

        res.cookie('accessToken', accessToken, {
            maxAge: 1000 * 60 *60 * 24,
            httpOnly : true
        })

        res.cookie('refreshToken', refreshToken, {
            maxAge: 1000 * 60 *60 * 24,
            httpOnly : true
        })

        const userDto = new UserDto(user)
        return res.status(200).json({user:userDto, auth: true});
    },

    async logout(req, res , next){
        // delete refresh token from db 
        let {refreshToken} = req.cookies;
        try {
            await RefreshToken.deleteOne({token: refreshToken})

        } catch (error) {
            return next(error)
        }

        // delete cookies
        res.clearCookie('accessToken')
        res.clearCookie('refreshToken')

        // response 
        return res.status(200).json({user: null, auth: false})

    },

    async refresh(req, res , next){
        // get refresh token from cookies
        const orignalRefreshToken = req.cookies.refreshToken;
        // verify refreshToken
        let id;
        try {
           id = JWTService.verifyRefreshToken(orignalRefreshToken)._id
        } catch (e) {
            const error = {
                status : 401,
                message : 'Unauthorized' 
            }
            return next(error)
        }

        try {
            const match = RefreshToken.findOne({_id: id, token: orignalRefreshToken})

            if(!match){
                const error = {
                    status: 401,
                    message: 'Unauthorized'
                }
                return next(error)
            }
        } catch (error) {
            return next(error)
        }

        // generate new tokens
        try {
            const accessToken = JWTService.signAccessToken({_id: id}, '30m');
            const refreshToken = JWTService.signRefreshToken({_id: id}, '60m');

            await RefreshToken.updateOne({_id:id}, {token: refreshToken})

            res.cookie('accessToken', accessToken, {
                maxAge: 1000 * 60 *60 *24,
                httpOnly: true
            })
            res.cookie('refreshToken', refreshToken, {
                maxAge: 1000 * 60 *60 *24,
                httpOnly: true
            })

        } catch (e) {
            return next(e)
        }

        const user = await User.findOne({_id: id});
        const  userDto = new UserDto(user);
        return res.status(200).json({user: userDto, auth: true})

    }
}

module.exports = authController;