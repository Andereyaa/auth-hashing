const prisma = require("../utils/prisma");

const createUser = async (username, hash) => {
  const newUser = await prisma.user.create({
    data: {
      username: username,
      password: hash,
    },
  });
  return newUser;
};

const getUserByUsername = async (username) => {
  return await prisma.user.findUnique({
    where: { username: username },
  });
};

module.exports = {
    createUser,
    getUserByUsername
}
