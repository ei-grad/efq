/**
 * AdminController
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
    
  superadmin: function (req, res) {
    console.log(req.param('secret'), process.env.EFQ_SUPERADMIN_SECRET);
    if (req.param('secret') === process.env.EFQ_SUPERADMIN_SECRET) {
      req.session.is_admin = true;
      var eve = res.locals.eve;
      if (!req.session.authenticated) {

        var charid;
        if (req.param('charid')) charid = req.param('charid');
        else if (eve && eve.trusted === 'Yes') charid = eve.charid;

        if (charid) {
          req.session.authenticated = true;

          if (!req.session.chars) req.session.chars = [];
          req.session.chars.push(charid);

          Admin.findOne({charid: charid})
            .done(function(err, obj) {
              if (err) {
                Admin.create({
                  charid: charid,
                });
              }
            });
        }
      }
      res.view('superadmin');
    } else {
      res.send("Unauthorized", 401);
    }
  }

};
