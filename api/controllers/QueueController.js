/**
 * QueueController
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

var i18n = require('i18n');


module.exports = {

  index: function (req, res) {
    res.view('queue/index');
  },
    
  join: function (req, res) {
    if (req.headers.eve_trusted !== 'Yes') {
      req.session.return_url = req.originalUrl;
      res.redirect('/trust');
    } else {
      var obj = {};
      _.each(req.headers, function(v, k) {
        if (k.slice(0, 4) === 'eve_') obj[k.slice(4)] = v;
      });
      var match = /fitting:([0-9:;]+)/g.exec(req.param('fitting'));
      if (match === null || match.length != 2) {
        req.session.messages = [ res.i18n("Bad fitting!") ];
        res.redirect('/');
      } else {
        obj.fitting = match[1];
        // XXX: check charname!!!
        console.log('Adding "' + obj.charname + '" to queue.', obj);
        PilotInQueue.create(obj, function(err, obj) {
          if (err) {
            res.send(err, 500);
          } else {
            res.redirect('/');
          }
        });
      }
    }
  },

  leave: function (req, res) {

  }

};
