var express = require('express');
var router = express.Router();
var mongoose = require('mongoose');
var bcrypt = require('bcrypt');

const User = require('../models/User');

//REGISTER A NEW USER
router.post('/register', (req, res) => {

    User.findOne({ username: req.body.username })
        .exec()
        .then(user => {
            if (user) {
                return res.status(409).json({
                    status: "exists",
                    message: "Username is taken"
                });
            } else {
                bcrypt.hash(req.body.password, 10, (err, hash) => {
                    if (err) {
                        return res.status(500).json({ error: err });
                    } else {
                        const user = new User({
                            username: req.body.username,
                            password: hash
                        });

                        user.save()
                            .then(result => {
                                res.json({ status: "ok", message: 'User created' });
                            })
                            .catch(error => {
                                res.status(500).json({ error: error })
                            });
                    }
                })
            }
        })
});

//USER LOGIN
router.post('/login', (req, res, next) => {
    User.findOne({ username: req.body.username })
        .then(user => {
            if (user) {
                bcrypt.compare(req.body.password, user.password, (err, response) => {
                    if (err) {
                        return res.status(401).json({ status: "wrong", message: "Authenitication failed" });
                    }
                    if (response) {
                        return res.json({ status: "ok", message: "Logged in" });
                    } else {
                        return res.status(401).json({ status: "wrong", message: "Authenitication failed" });
                    }
                });
            } else {
                return res.status(401).json({ status: "wrong", message: "Authenitication failed" });
            }
        })
        .catch(err => {
            res.status(500).json({ error: err });
        });
});

module.exports = router;