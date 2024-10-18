const express = require('express')
const dotenv = require('dotenv')

dotenv.config();

const app = express();

app.use(express.json());

const authRoutes = require('./routes/authRoutes');
app.use('/api/auth', authRoutes); 

app.get('/', (req, res) => {
    res.send('Welcome to Collingo API');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
})