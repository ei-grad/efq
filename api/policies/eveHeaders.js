module.exports = function eveHeaders (req, res, next) {
  var obj = {};
  for (var k in req.headers) {
    if (k.slice(0, 4) === 'eve_') obj[k.slice(4)] = req.headers[k];
  }
  res.locals.eve = obj;
  next();
};
