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

  join: function (req, res) {

    var match = /fitting:([0-9:;]+)/g.exec(req.param('fitting'));
    if (match === null || match.length != 2 || match[1].length === 0) {
      req.session.messages = [ res.i18n("Bad fitting!") ];
      res.redirect('/');
      return;
    }

    var obj = _.clone(res.locals.eve);

    obj.fitting = match[1];

    console.log("Updating #" + obj.id + " to ", obj);

    // XXX: check req.session.charname!

    PilotInQueue.findOne({charid: obj.charid}, function (err, found) {
      console.log('PilotInQueue.findOne: ', err, found);
      if (found === undefined) {
        PilotInQueue.create(obj, function(err, created) {
          console.log('PilotInQueue.create: ', err, created);
          if (err) {
            console.log(err);
            res.send(err, 500);
          } else {
            PilotInQueue.publishCreate(created.toJSON());
            res.redirect('/');
          }
        });
      } else {
        PilotInQueue.update({charid: obj.charid}, obj, function(err, updated) {
          console.log('PilotInQueue.update: ', err, updated);
          if (err) {
            console.log(err);
            res.send(err, 500);
          } else {
            console.log(updated[0]);
            PilotInQueue.publishUpdate(updated[0].id, );
            res.redirect('/');
          }
        });
      }
    });

  },

  leave: function (req, res) {
    res.send('Not Implemented Yet', 500);
  },

  invite: function (req, res) {
    res.send('Not Implemented Yet', 500);
  },

  kick : function (req, res) {
    res.send('Not Implemented Yet', 500);
  },

};
