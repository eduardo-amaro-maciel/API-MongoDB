require('dotenv').config()

const mongoose = require('mongoose')
const User = require('./models/User')

const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const express = require('express')
const cors = require('cors')
const logServer = require('./creatLog')

logServer.createLog()

const app = express()

app.use(express.json())
app.use(cors())

const PORT = process.env.PORT
const DB_USER = process.env.DB_USER
const DB_PASS = process.env.DB_PASS
const DB_URL = `mongodb+srv://${DB_USER}:${DB_PASS}@cluster0.viiq9oo.mongodb.net/?retryWrites=true&w=majority`

mongoose.connect(DB_URL)
    .then(() => { console.log('conectou') })
    .catch((err) => {  console.log(err) })


function checkToken(req, res, next) {

    try {
        const SECRET = process.env.SECRET
        const authHeader = req.headers['authorization']
        const token = authHeader && authHeader.split(' ')[1]

        jwt.verify(token, SECRET)
        next()

    } catch (err) {
        res.status(400).json({ msg: 'O token é invalido' })
    }
}

app.get('/', (req, res)  => {
    logServer.writeLog('/', req.socket.remoteAddress, req.get('User-Agent'))

    try {
        res.status(200).json({ "msg": "Bem vindo" })
    } catch(err) {

        res.status(400).json({ "msg": err })
    }
})


/* ROTA PRIVADA -> pegar usuario por id */
app.get('/user/getUser/:id', checkToken, async (req, res) => {
    logServer.writeLog('/user/getUser/:id', req.socket.remoteAddress, req.get('User-Agent'))

    try {
        const user = await User.findById(req.params.id, '-password')
        res.status(200).json({ user })

    } catch(err) {
        return res.status(404).json({ msg: err }) 
    }
})


/* ROTA PRIVADA -> pegar todos os usuarios */
app.get('/user/getAllUsers', checkToken, async (req, res) => {
    logServer.writeLog('/user/getAllUsers', req.socket.remoteAddress, req.get('User-Agent'))
    
    try {
        const user = await User.find()
        res.status(200).json({ user })
        
    } catch (err) {
        return res.status(404).json({ msg: err })
    }
})


/* ROTA PRIVADA -> deltar usuario por id */
app.delete('/user/deleteUser/:id', checkToken, async (req, res) => {
    logServer.writeLog('/user/deleteUser/:id', req.socket.remoteAddress, req.get('User-Agent'))

    try {
        await User.findByIdAndDelete(req.params.id)
        res.status(200).json({ msg: 'Usuario deletado com sucesso!' })

    } catch (err) {
        res.status(500).json({ msg: err })
    }
})


/* ROTA PRIVADA -> upadte usuario por id */
app.put('/user/updateUser/:id', checkToken, async (req, res) => {
    logServer.writeLog('/user/updateUser/:id', req.socket.remoteAddress, req.get('User-Agent'))

    try {
        const fieldsUpdate = {}

        if (req.body.name) fieldsUpdate['name'] = req.body.name 
        if (req.body.email) fieldsUpdate['email'] = req.body.email 
        if (req.body.password) {
            // criando a senha mais forte
            const salt = await bcrypt.genSalt(12)
            const passwordHash = await bcrypt.hash(req.body.password, salt)
            fieldsUpdate['password'] = passwordHash
        }

        await User.findByIdAndUpdate(req.params.id, fieldsUpdate)

        res.status(200).json({ msg: 'Usuario atualizado com sucesso!' })

    } catch(err) {
        res.status(400).json({ msg: err })
    }
})


app.post('/auth/register', async (req, res) => {
    logServer.writeLog('/auth/register', req.socket.remoteAddress, req.get('User-Agent'))

    try {
        const { name, email, password, confirmpassword } = req.body

        if (!name) return res.status(422).json({ msg: 'O nome é obrigatorio' }) 
        if (!email) return res.status(422).json({ msg: 'O email é obrigatorio' }) 
        if (!password) return res.status(422).json({ msg: 'A senha é obrigatorio' }) 
        if (password !== confirmpassword) return res.status(422).json({ msg: 'As senhas não conferem' }) 

        const userExists = await User.findOne({ email: email })
        if (userExists) return res.status(422).json({ msg: 'Por favor utilize outro e-mail' }) 

        // criando a senha mais forte
        const salt = await bcrypt.genSalt(12)
        const passwordHash = await bcrypt.hash(password, salt)

        const user = new User({ name, email, password: passwordHash })
        await user.save()
        res.status(201).json({ msg: 'usuario criado com sucesso' })

    } catch (err) {
        res.status(500).json({ msg: err }) 
    }
})


app.post('/auth/login', async (req, res) => {
    logServer.writeLog('/auth/login', req.socket.remoteAddress, req.get('User-Agent'))

    try {
        const { email, password } = req.body
        const user = await User.findOne({ email: email })
        const checkPassword = await bcrypt.compare(password, user.password)

        if (!email) return res.status(422).json({ msg: 'O email é obrigatorio' }) 
        if (!password) return res.status(422).json({ msg: 'A senha é obrigatorio' }) 
        if (!user) return res.status(422).json({ msg: 'Usuario não encontrao' }) 
        if (!checkPassword) return res.status(422).json({ msg: 'Usuario não encontrao' }) 

        const secret = process.env.SECRET
        const token = jwt.sign({ id: user._id }, secret )
        res.status(200).json({ msg: 'Autenticação ok', token })

    } catch (err) {
        res.status(500).json({ msg: err }) 
    }
})

app.listen(PORT || 3000, () => { console.log(`Server rodando na porta ${ PORT }`) })