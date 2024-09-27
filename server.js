const express = require('express')
const dbConnect = require('./database')
const { PORT } = require('./config')
const router = require('./routes')
const errorHandler = require('./middleware/errorHandler')
const cookieParser = require('cookie-parser')

const app = express()

app.use(cookieParser())
app.use(express.json())
app.use(router)

dbConnect();
app.use('/storage', express.static('storage'))
app.use(errorHandler)

app.listen(PORT, () => {
    console.log(`App is listening on port ${PORT}`);
})
