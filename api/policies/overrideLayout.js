module.exports = function overrideLayout (req, res, next) {
  if (req.headers["x-requested-with"] === "XMLHttpRequest") res.locals.layout = 'empty.ejs';
  next();
};
