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

  info: function (req, res) {

    var ret = {
      trusted: res.locals.eve.trusted === "Yes",
      authenticated: (req.session.authenticated === true) && (req.session.chars.indexOf(res.locals.eve.charid) !== -1),
    };

    if (!ret.trusted || !ret.authenticated) {
      ret.state = 'guest';
      console.log('info:', ret);
      console.log('info:', ret);
      console.log('chars:', req.session.chars);
      res.json(ret);
    } else PilotInQueue.findOne({
      charid: res.locals.eve.charid
    }, function (err, found) {
      if (err) { console.log(err); res.send(err, 500); }
      else {
        if (found) ret.state = 'anticipant';
        else ret.state = 'spectrator';
        console.log('info:', ret);
        res.json(ret);
      }
    });
  },

  join: function (req, res) {

    var obj = _.clone(res.locals.eve);

    // XXX: move to policy
    if (req.session.chars.indexOf(obj.charid) === -1) {
      console.log("Not authenticated: headers.charid=" + obj.charid + ", but session.chars: " + req.session.chars);
      req.session.messages = [
        res.i18n("you have to be authenticated as ") + obj.charname + "!"
      ];
      res.redirect('/');
      return;
    }

    var match = /fitting:([0-9:;]+)/g.exec(req.param('fitting'));
    if (match === null || match.length != 2 || match[1].length === 0) {
      console.log("Bad fitting: ", req.param('fitting'));
      req.session.messages = [ res.i18n("Bad fitting!") ];
      res.redirect('/');
      return;
    }

    obj.fitting = match[1];

    PilotInQueue.findOne({charid: obj.charid}, function (err, found) {
      if (found === undefined) {
        PilotInQueue.create(obj, function(err, created) {
          if (err) { console.log(err); res.send(err, 500); }
          else {
            console.log('Pilot joined queue: ', created);
            PilotInQueue.publishCreate(created.toJSON());
            res.redirect('/');
          }
        });
      } else {
        console.log('Pilot ' + found.charname + ' is already in queue.');
        res.send("You are already in the queue.", 400);
      }
    });

  },

  update: function(req, res) {

    var obj = _.clone(res.locals.eve);

    // XXX: move to policy
    if (req.session.chars.indexOf(obj.charid) === -1) {
      // TODO: write a messages controller!
      req.session.messages = [
        res.i18n("you have to be authenticated as ") + obj.charname + "!"
      ];
      res.redirect('/');
      return;
    }

    if (req.param('fitting')) {
      var match = /fitting:([0-9:;]+)/g.exec(req.param('fitting'));
      if (match === null || match.length != 2 || match[1].length === 0) {
        req.session.messages = [ res.i18n("Bad fitting!") ];
        res.redirect('/');
        return;
      }

      obj.fitting = match[1];
    }

    PilotInQueue.update({charid: obj.charid}, function (err, updated) {
      if (err) { console.log(err); res.send(err, 500); }
      else {
        PilotInQueue.publishUpdate(obj);
        res.redirect('/');
      }
    });

  },

  leave: function (req, res) {
    PilotInQueue.findOne({charid: res.locals.eve.charid}, function(err, obj) {
      if (err) { console.log(err); res.send(err, 500); }
      else obj.destroy(function(err) {
        if (err) { console.log(err); res.send(err, 500); }
        else {
          PilotInQueue.publishDestroy(obj.id);
          res.redirect('/');
        }
      });
    });
  },

  invite: function (req, res) {
    res.send('Not Implemented Yet', 500);
  },

  kick : function (req, res) {
    res.send('Not Implemented Yet', 500);
  },

};
