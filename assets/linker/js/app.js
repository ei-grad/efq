(function (io) {

  // as soon as this file is loaded, connect automatically, 
  var socket = io.connect();

  log('Connecting to Sails.js...');

  socket.on('connect', function socketConnected() {

    ///////////////////////////////////////////////////////////
    // Here's where you'll want to add any custom logic for
    // when the browser establishes its socket connection to 
    // the Sails.js server.
    ///////////////////////////////////////////////////////////
    log('Connected!');
    ///////////////////////////////////////////////////////////

  });

  // Expose connected `socket` instance globally so that it's easy
  // to experiment with from the browser console while prototyping.
  window.socket = socket;




})(

  // In case you're wrapping socket.io to prevent pollution of the global namespace,
  // you can replace `window.io` with your own `io` here:
  window.io

);


function log () {
  if (typeof console !== 'undefined') {
    console.log.apply(console, arguments);
  }
}


var convertToDate = {
  create: function(options) { 
    return ko.observable(moment(options.data));
  }
};


var now = ko.observable(moment());
setInterval(function() { self.now(moment()); }, 60 * 1000);


function PilotInQueueModel(data) {
  var self = this;
  ko.mapping.fromJS(data, {
    key: function(data) { return ko.utils.unwrapObservable(data.id); },
    createdAt: convertToDate,
    updateAt: convertToDate,
  }, self);
  self.fromNow = ko.computed(function() {
    return moment(self.createdAt()).from(now());
  });
  log("Created new PilotInQueueModel:", self);
}


function QueueViewModel() {
  var self = this;

  /* ===============
   * Data definition
   * =============== */

  // use special observable

  self.fitting = ko.observable();
  self.pilots = ko.mapping.fromJS([], {
    create: function(options) { return new PilotInQueueModel(options.data); }
  });
  self.messages = ko.observableArray([]);
  self.sortedPilots = ko.computed(function () {
    return self.pilots().sort(function(a, b) {
      return a.createdAt - b.createdAt;
    });
  });

  // Load data
  socket.get("/pilotinqueue", function(data) {
    log("Pilots loaded:", data);
    ko.mapping.fromJS(data, {}, self.pilots);
  });

  var message_handlers = {
    pilotinqueue: {
      create: function (e) { self.pilots.mappedCreate(e.data); },
      destroy: function (e) { self.pilots.mappedRemove({id: e.id}); },
    }
  };

  // Listen for Comet messages from Sails
  socket.on('message', function messageReceived(e) {
    log('New event received :: ', e);
    try {
      message_handlers[e.model][e.verb](e);
    } catch (err) {
      log("Error:", err);
    }
  });

}

ko.bindingHandlers.fitting = {
  update: function(element, valueAccessor, allBindings, viewModel, bindingContext) {
    var data = ko.unwrap(valueAccessor());
    var fitting = ko.unwrap(data.fitting);
    var el = $(element);
    if (fitting) {
      var a = el.find('a');
      if (a[0] === undefined) {
        a = $('<a>').appendTo(el);
      }
      el = a;
      el.attr('href', 'javascript:CCPEVE.showFitting("' + fitting + '");');
    }
    el.text(ko.unwrap(data.shipname));
  }
};

ko.bindingHandlers.solarsystem = {
  update: function(element, valueAccessor, allBindings, viewModel, bindingContext) {
    var data = ko.unwrap(valueAccessor());
    var name = ko.unwrap(data.solarsystemname);
    var id = ko.unwrap(data.solarsystemid);
    var el = $(element);
    var a = el.find('a');
    if (a[0] === undefined) {
      a = $('<a>').appendTo(el);
    }
    el = a;
    el.attr('href', 'javascript:CCPEVE.showInfo(5, ' + id + ');');
    el.text(name);
  }
}

ko.applyBindings(new QueueViewModel());
