/**
 * AuthController
 *
 * @module      :: Controller
 * @description	:: A set of functions called `actions`.
 *
 *                 Actions contain code telling Sails how to respond to a certain type of request.
 *                 (i.e. do stuff, then send some JSON, show an HTML page, or redirect to another URL)
 *
 *                 You can configure the blueprint URLs which trigger these actions (`config/controllers.js`)
 *                 and/or override them with custom routes (`config/routes.js`)
 *
 *                 NOTE: The code you write here supports both HTTP and Socket.io automatically.
 *
 * @docs        :: http://sailsjs.org/#!documentation/controllers
 */

module.exports = {
    
  logout: function (req, res) {
    if (req.session.authenticated) {
      req.session.authenticated = false;
      if (res.locals.eve) {
        delete req.session.chars[res.locals.eve.charid];
      }
    }
    res.redirect('/');
  },

  /**
   * Overrides for the settings in `config/controllers.js`
   * (specific to AuthController)
   */
  _config: {}

  
};

if(process.env.EFQ_AUTH_USE_EVE_CHARID) {
  module.exports.login = function (req, res) {
    if (res.locals.eve.trusted === 'Yes') {
      req.session.authenticated = true;
      if (!req.session.chars) req.session.chars = [];
      req.session.chars.push(res.locals.eve.charid);
      res.redirect('/');
    } else {
      res.redirect('/trust');
    }
  };
}
