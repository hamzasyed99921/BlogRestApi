const express = require('express');
const authController = require('../controller/authController');
const auth = require('../middleware/auth');
const blogController = require('../controller/blogController');
const commentController = require('../controller/commentController');

const router = express.Router();

router.get('/test', (req,res) => {
    res.json({msg: 'Hello'})
})

// Users

// register
router.post("/register", authController.register)

// login
router.post("/login", authController.login)

// logout
router.post("/logout", auth, authController.logout)

// refresh
router.get("/refresh", authController.refresh)


// Blog Apis

// create
router.post('/blog', auth, blogController.create)

// get all
router.get('/blog/all', auth, blogController.getAll);

// getById
router.get('/blog/:id', auth , blogController.getById);

// update blog
router.put('/blog', auth , blogController.update);

// delete blog
router.delete('/blog/:id', auth, blogController.delete)


// Comment Routes
// create
router.post('/comment', auth, commentController.create)
// get by id
router.get('/comment/:id', auth, commentController.getById)

module.exports = router;