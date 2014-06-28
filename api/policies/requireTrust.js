module.exports = function requireTrust (req, res, next) {
  if (req.headers.eve_trusted !== 'Yes') {
    req.session.trust_return_url = req.originalUrl;
    res.redirect('/trust');
    return;
  } 
  var obj = {};
  for (var k in req.headers) {
    if (k.slice(0, 4) === 'eve_') obj[k.slice(4)] = req.headers[k];
  }
  req.locals.eve = obj;
  next();
};
