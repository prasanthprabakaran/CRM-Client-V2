import jwt from "jsonwebtoken";

const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization || req.headers.Authorization

  if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Unauthorized' })
  }

  const token = authHeader.split(' ')[1]

  jwt.verify(
      token,
      process.env.ACCESS_TOKEN_SECRET,
      (err, decoded) => {
          if (err) return res.status(403).json({ message: 'Forbidden' })
          req.user = decoded.UserInfo.username
          req.roles = decoded.UserInfo.roles
          next()
      }
  )
}

export default verifyJWT;






// const verfiyJWT = async (req, res, next) => {
//   const authHeader =
//     req.headers.authorization || req.headers.Authorization
//   const [type, token] = authHeader.split(" ")[1];
//   if (type === "Bearer" && typeof token !== "undefined") {
//     try {
//       jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
//         if (err) return res.status(400).json({ message: "Forbidden" });
//         req.user = decoded.UserInfo.username;
//         req.roles = decoded.UserInfo.roles;
//         next();
//       });
//     } catch (err) {
//       res.status(401).send({ message: "Invalid or expired token" });
//     }
//   } else {
//     res.status(401).send({ message: "Invalid token" });
//   }
//   return authHeader;
// };

