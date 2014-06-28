/**
 * TrustController
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
    
  'index': function (req, res) {
    if (req.headers.eve_trusted !== 'Yes') {
      res.view('trust', {
        host: req.headers.host,
      });
    } else {
      var url = req.session.trust_return_url;
      delete req.session.trust_return_url;
      res.redirect(url);
    }
  },


  /**
   * Overrides for the settings in `config/controllers.js`
   * (specific to TrustController)
   */
  _config: {}

  
};
