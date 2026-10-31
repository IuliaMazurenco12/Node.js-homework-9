export function checkMustChangePassword(req, res, next) {
  if (req.user.mustChangePassword) {
    return res.redirect('/change-password');
  }
  next();
}