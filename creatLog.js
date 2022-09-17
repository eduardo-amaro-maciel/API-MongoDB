const fs = require('fs')
const { log } = require('util')
const contentFilePath = './logServer.txt'

const logServer = {

    createLog() {
        fs.appendFile(contentFilePath, '', err => {
            if (err) console.log(err)
        })

        logServer.loadLog()
    },

    loadLog() {
        fs.readFileSync(contentFilePath, 'utf-8')
    },

    writeLog(content, ip, userAgent) {

        const date = new Date()
        let time = `[${date.getDate().toLocaleString()}/${date.getMonth()}/${date.getFullYear()} `
            time += `${date.getHours()}-${date.getMinutes()}-${date.getSeconds()}] `
            time += `route :: ['${content}'] `
            time += `timestamp :: ${date.getTime()} | `
            time += `ip :: ${ip.replace('::', '')} `
            time += `[User-Agent] :: ${userAgent}\n`

        fs.appendFileSync(contentFilePath, time)
    }
}

module.exports = logServer