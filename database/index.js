const mongoose = require('mongoose');
const { URI } = require('../config');


const dbConnect = async () => {
    try {
    const conn = await mongoose.connect(URI)
    console.log(`Database Connected ${conn.connection.host}`);
    
        
    } catch (error) {
        console.log(`Error ${error}`);
    }
}

module.exports = dbConnect;
