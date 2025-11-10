import passport from 'passport'
import express from 'express'

export default function ({ db, config }) {
  const router = express.Router()

  router.get('/', async (req, res) => {
    if (req.isAuthenticated()) {
      res.redirect('/')
      return
    }

    // Collect all usernames (document IDs) from the users DB and pass to the view
    let usernames = []
    try {
      const result = await db.allDocs()
      usernames = (result.rows || []).map((r) => r.id)
    } catch (err) {
      // If the DB isn't available or empty, render without usernames
      usernames = []
    }

    res.render('login', {
      oidcEnabled: config.oidcEnabled,
      usernames,
      passwordlessLogin: config.passwordlessLogin,
    })
  })

  // Passwordless login (development helper). Clicking a username button will log in
  // as that user if `config.passwordlessLogin` is true or NODE_ENV is 'development'.
  router.post('/as', async (req, res) => {
    const allow = config.passwordlessLogin || process.env.NODE_ENV === 'development'
    if (!allow) {
      req.flash('error', 'Passwordless login disabled')
      return res.redirect('/login')
    }

    const username = (req.body && req.body.username) || req.query.username
    if (!username) {
      req.flash('error', 'No username provided')
      return res.redirect('/login')
    }

    try {
      const user = await db.get(username)
      req.logIn(user, (err) => {
        if (err) {
          req.flash('error', 'Login failed')
          return res.redirect('/login')
        }
        return res.redirect('/')
      })
    } catch (err) {
      req.flash('error', 'User not found')
      return res.redirect('/login')
    }
  })

  router.post(
    '/',
    (_req, _res, next) => {
      next()
    },
    passport.authenticate('local', {
      successRedirect: '/',
      failureRedirect: '/login',
      failureFlash: 'Invalid username or password',
    }),
  )
  return router
}
