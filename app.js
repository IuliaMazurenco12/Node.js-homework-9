import "dotenv/config";
import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import sequelize from "./config/db.js";
import User from "./models/user.js";
import { authenticate } from "./middlewares/authenticate.js";
import { checkMustChangePassword } from "./middlewares/checkMustChangePassword.js";
import { isAdmin } from "./middlewares/isAdmin.js";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get("/", (req, res) => {
  res.send("Server is working!");
});

// Задача 1 - регистрация
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    // 1. Проверяем, что данные переданы
    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Нужно передать email и password" });
    }

    // 2. Проверяем уникальность email
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res
        .status(409)
        .json({ message: "Этот email уже зарегистрирован" });
    }

    // 3. Хешируем пароль
    const hashedPassword = await bcrypt.hash(password, 10);

    // 4. Создаём пользователя
    const user = await User.create({ email, password: hashedPassword });

    res.status(201).json({
      message: "Пользователь успешно зарегистрирован",
      user: { id: user.id, email: user.email },
    });
  } catch (error) {
    if (error.name === "SequelizeValidationError") {
      return res.status(400).json({ message: "Некорректный email" });
    }
    res.status(500).json({ message: "Ошибка сервера", error: error.message });
  }
});

// Вход
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Нужно передать email и password" });
    }

    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({ message: "Неверный email или пароль" });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(401).json({ message: "Неверный email или пароль" });
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({
      message: "Вход выполнен",
      token,
      mustChangePassword: user.mustChangePassword,
    });
  } catch (error) {
    res.status(500).json({ message: "Ошибка сервера", error: error.message });
  }
});

// ===== Задача 2: страница смены пароля =====
app.get("/change-password", (req, res) => {
  res.json({
    message:
      "Необходимо сменить пароль. Отправьте POST /change-password с полем newPassword",
  });
});

//  Задача 2: смена пароля
app.post("/change-password", authenticate, async (req, res) => {
  try {
    const { newPassword } = req.body || {};

    if (!newPassword || newPassword.length < 6) {
      return res
        .status(400)
        .json({ message: "Новый пароль должен быть не короче 6 символов" });
    }

    req.user.password = await bcrypt.hash(newPassword, 10);
    req.user.mustChangePassword = false;
    await req.user.save();

    res.json({ message: "Пароль успешно изменён" });
  } catch (error) {
    res.status(500).json({ message: "Ошибка сервера", error: error.message });
  }
});

// защищённый маршрут для проверки
app.get("/profile", authenticate, checkMustChangePassword, (req, res) => {
  res.json({
    message: "Добро пожаловать в профиль",
    user: { id: req.user.id, email: req.user.email },
  });
});

// Задача 3: удаление аккаунта
app.post(
  "/delete-account",
  authenticate,
  checkMustChangePassword,
  async (req, res) => {
    try {
      const { password } = req.body || {};

      if (!password) {
        return res.status(400).json({ message: "Введите текущий пароль" });
      }

      const isPasswordCorrect = await bcrypt.compare(
        password,
        req.user.password,
      );
      if (!isPasswordCorrect) {
        return res.status(401).json({ message: "Неверный пароль" });
      }

      await req.user.destroy();

      res.json({ message: "Аккаунт успешно удалён" });
    } catch (error) {
      res.status(500).json({ message: "Ошибка сервера", error: error.message });
    }
  },
);

// Задача 4: только для администраторов
app.get(
  "/admin",
  authenticate,
  checkMustChangePassword,
  isAdmin,
  (req, res) => {
    res.json({ message: `Добро пожаловать в админ-панель, ${req.user.email}` });
  },
);

//Задача 5: смена email
app.post(
  "/change-email",
  authenticate,
  checkMustChangePassword,
  async (req, res) => {
    try {
      const { newEmail, password } = req.body || {};

      if (!newEmail || !password) {
        return res
          .status(400)
          .json({ message: "Нужно передать newEmail и password" });
      }

      // 1. Проверяем пароль
      const isPasswordCorrect = await bcrypt.compare(
        password,
        req.user.password,
      );
      if (!isPasswordCorrect) {
        return res.status(401).json({ message: "Неверный пароль" });
      }

      // 2. Проверяем уникальность нового email
      const existingUser = await User.findOne({ where: { email: newEmail } });
      if (existingUser) {
        return res.status(409).json({ message: "Этот email уже используется" });
      }

      // 3. Обновляем email
      req.user.email = newEmail;
      await req.user.save();

      res.json({ message: "Email успешно изменён", email: req.user.email });
    } catch (error) {
      if (error.name === "SequelizeValidationError") {
        return res.status(400).json({ message: "Некорректный email" });
      }
      res.status(500).json({ message: "Ошибка сервера", error: error.message });
    }
  },
);

//Запуск
sequelize
  .authenticate()
  .then(() => sequelize.sync({ alter: true }))
  .then(() => {
    console.log("База данных подключена и синхронизирована");
    app.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Ошибка базы данных:", error.message);
  });
