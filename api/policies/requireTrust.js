module.exports = function requireTrust (req, res, next) {
  if (req.headers.eve_trusted !== 'Yes') {
    req.session.trust_return_url = req.originalUrl;
    res.redirect('/trust');
    return;
  }
  next();
};
