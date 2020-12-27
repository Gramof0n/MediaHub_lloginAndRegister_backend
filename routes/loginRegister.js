var express = require('express');
var router = express.Router();
var mongoose = require('mongoose');
var bcrypt = require('bcrypt');

const jwt = require('jsonwebtoken');
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
                        const token = jwt.sign(
                            {
                                isAdmin: user.isAdmin,
                                id: user._id,
                                username: user.username
                            },
                            process.env.JWT_KEY,
                            {
                                expiresIn: "1h"
                            }
                        );
                        return res.json({ status: "ok", message: "Logged in", token: token });
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