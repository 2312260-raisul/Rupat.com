import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { z } from 'zod';
import { GoogleGenAI } from '@google/genai';
import { dbInstance, hashPassword, generateSalt, User, Product, Order, SystemSettings } from './src/server/db.ts';

const app = express();
const PORT = 3000;

app.use(express.json());

// ============================================================================
// ZOD VALIDATION SCHEMAS
// ============================================================================

const LoginSchema = z.object({
  email: z.string().email({ message: "Invalid email format" }),
  password: z.string().min(6, { message: "Password must be at least 6 characters" })
});

const RegisterSchema = z.object({
  name: z.string().min(2, { message: "Name must be at least 2 characters" }),
  email: z.string().email({ message: "Invalid email format" }),
  password: z.string().min(6, { message: "Password must be at least 6 characters" })
});

const ProductSchema = z.object({
  name: z.string().min(3, { message: "Product name must be at least 3 characters" }),
  sku: z.string().min(3, { message: "SKU must be at least 3 characters" }),
  description: z.string().min(10, { message: "Description must be at least 10 characters" }),
  ingredients: z.string().min(5, { message: "Ingredients list is required" }),
  skinType: z.enum(['Oily', 'Dry', 'Combination', 'Sensitive', 'All']),
  price: z.number().positive({ message: "Price must be a positive number" }),
  stockCount: z.number().int().nonnegative({ message: "Stock count cannot be negative" }),
  images: z.array(z.string().url()).min(1, { message: "At least one image URL is required" }),
  categories: z.array(z.string()).min(1, { message: "At least one category is required" }),
  preferences: z.array(z.string())
});

const CheckoutSchema = z.object({
  items: z.array(z.object({
    productId: z.string(),
    name: z.string(),
    price: z.number().positive(),
    quantity: z.number().int().positive(),
    image: z.string()
  })).min(1, { message: "Your shopping cart is empty" }),
  shippingAddress: z.object({
    fullName: z.string().min(2, { message: "Full name is required" }),
    street: z.string().min(5, { message: "Street address is required" }),
    city: z.string().min(2, { message: "City is required" }),
    state: z.string().min(2, { message: "State/Province is required" }),
    zipCode: z.string().min(3, { message: "Valid zip/postal code is required" }),
    country: z.string().min(2, { message: "Country is required" })
  }),
  promoCode: z.string().optional()
});

// ============================================================================
// AUTHENTICATION & RBAC MIDDLEWARES
// ============================================================================

export interface AuthenticatedRequest extends Request {
  user?: User;
  token?: string;
}

// Authenticates standard users via token
const authenticateToken = (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    res.status(401).json({ message: "Access denied. authentication token missing." });
    return;
  }

  const userId = dbInstance.getUserIdByToken(token);
  if (!userId) {
    res.status(401).json({ message: "Session expired or invalid token." });
    return;
  }

  const user = dbInstance.getUserById(userId);
  if (!user) {
    res.status(401).json({ message: "User account no longer exists." });
    return;
  }

  req.user = user;
  req.token = token;
  next();
};

// Roles check: Manager or Admin
const requireManagerOrAdmin = (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
  if (!req.user || (req.user.role !== 'manager' && req.user.role !== 'admin')) {
    res.status(403).json({ message: "Access forbidden. Requires Store Manager or Admin access." });
    return;
  }
  next();
};

// Roles check: Admin only
const requireAdmin = (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
  if (!req.user || req.user.role !== 'admin') {
    res.status(403).json({ message: "Access forbidden. Strictly restricted to Super Admin role." });
    return;
  }
  next();
};

// ============================================================================
// BACKEND API ROUTES
// ============================================================================

// 1. AUTHENTICATION ENDPOINTS
app.post('/api/auth/register', (req: Request, res: Response) => {
  const result = RegisterSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ errors: result.error.issues });
    return;
  }

  const { name, email, password } = result.data;

  const existingUser = dbInstance.getUserByEmail(email);
  if (existingUser) {
    res.status(400).json({ message: "An account with this email already exists." });
    return;
  }

  const salt = generateSalt();
  const passwordHash = hashPassword(password, salt);

  const newUser = dbInstance.createUser({
    name,
    email,
    passwordHash,
    salt,
    role: 'customer' // Defaults to regular customer
  });

  const token = dbInstance.createSession(newUser.id);
  
  res.status(201).json({
    token,
    user: { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role }
  });
});

app.post('/api/auth/login', (req: Request, res: Response) => {
  const result = LoginSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ errors: result.error.issues });
    return;
  }

  const { email, password } = result.data;
  const user = dbInstance.getUserByEmail(email);

  if (!user) {
    res.status(401).json({ message: "Invalid email or password." });
    return;
  }

  const hashedInput = hashPassword(password, user.salt);
  if (hashedInput !== user.passwordHash) {
    res.status(401).json({ message: "Invalid email or password." });
    return;
  }

  const token = dbInstance.createSession(user.id);

  res.json({
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role }
  });
});

app.post('/api/auth/logout', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
  if (req.token) {
    dbInstance.destroySession(req.token);
  }
  res.json({ message: "Logged out successfully." });
});

app.get('/api/auth/me', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    res.status(401).json({ message: "Not authenticated" });
    return;
  }
  res.json({
    user: { id: req.user.id, name: req.user.name, email: req.user.email, role: req.user.role }
  });
});

// 2. PRODUCT MANAGEMENT ENDPOINTS
app.get('/api/products', (req: Request, res: Response) => {
  res.json(dbInstance.getProducts());
});

app.get('/api/products/:id', (req: Request, res: Response) => {
  const product = dbInstance.getProductById(req.params.id);
  if (!product) {
    res.status(404).json({ message: "Cosmetics product not found." });
    return;
  }
  res.json(product);
});

// Create product (Manager / Admin)
app.post('/api/products', authenticateToken, requireManagerOrAdmin, (req: AuthenticatedRequest, res: Response) => {
  const result = ProductSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ errors: result.error.issues });
    return;
  }

  const newProduct = dbInstance.createProduct(result.data);
  res.status(201).json(newProduct);
});

// Update product (Manager / Admin)
app.put('/api/products/:id', authenticateToken, requireManagerOrAdmin, (req: AuthenticatedRequest, res: Response) => {
  const result = ProductSchema.partial().safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ errors: result.error.issues });
    return;
  }

  const updatedProduct = dbInstance.updateProduct(req.params.id, result.data);
  if (!updatedProduct) {
    res.status(404).json({ message: "Cosmetics product not found or failed to update." });
    return;
  }
  res.json(updatedProduct);
});

// Delete product (Manager / Admin)
app.delete('/api/products/:id', authenticateToken, requireManagerOrAdmin, (req: AuthenticatedRequest, res: Response) => {
  const success = dbInstance.deleteProduct(req.params.id);
  if (!success) {
    res.status(404).json({ message: "Cosmetics product not found." });
    return;
  }
  res.json({ message: "Cosmetics product deleted successfully." });
});

// 3. ORDER ENDPOINTS
// Place order (any authenticated user)
app.post('/api/orders', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
  const result = CheckoutSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ errors: result.error.issues });
    return;
  }

  const { items, shippingAddress, promoCode } = result.data;
  const user = req.user!;
  const settings = dbInstance.getSettings();

  // Calculate totals
  let subtotal = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
  
  // Apply promo code discount if valid
  let discount = 0;
  if (promoCode) {
    const promo = settings.discountCodes.find(d => d.code.toUpperCase() === promoCode.toUpperCase() && d.active);
    if (promo) {
      discount = subtotal * (promo.discountPercent / 100);
      subtotal -= discount;
    }
  }

  const taxAmount = Number((subtotal * (settings.taxRate / 100)).toFixed(2));
  const totalAmount = Number((subtotal + taxAmount).toFixed(2));

  // Build and save order
  const newOrder = dbInstance.createOrder({
    customerId: user.id,
    customerName: user.name,
    customerEmail: user.email,
    items,
    totalAmount,
    taxAmount,
    shippingAddress,
    paymentStatus: 'Paid', // Dummy instant payment confirmation
    shippingStatus: 'Pending'
  });

  res.status(201).json(newOrder);
});

// Get logged-in user's orders
app.get('/api/orders/my', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
  const myOrders = dbInstance.getOrders().filter(o => o.customerId === req.user!.id);
  res.json(myOrders);
});

// Get all orders (Manager / Admin)
app.get('/api/orders', authenticateToken, requireManagerOrAdmin, (req: AuthenticatedRequest, res: Response) => {
  res.json(dbInstance.getOrders());
});

// Update order shipping/payment status (Manager / Admin)
app.patch('/api/orders/:id', authenticateToken, requireManagerOrAdmin, (req: AuthenticatedRequest, res: Response) => {
  const statusSchema = z.object({
    shippingStatus: z.enum(['Pending', 'Shipped', 'Delivered', 'Cancelled']).optional(),
    paymentStatus: z.enum(['Pending', 'Paid', 'Failed']).optional()
  });

  const result = statusSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ errors: result.error.issues });
    return;
  }

  const updatedOrder = dbInstance.updateOrderStatus(req.params.id, result.data);
  if (!updatedOrder) {
    res.status(404).json({ message: "Order not found." });
    return;
  }
  res.json(updatedOrder);
});

// 4. USER/STAFF MANAGEMENT (Admin Only)
app.get('/api/users', authenticateToken, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  // Return users list excluding passwords and salts
  const publicUsers = dbInstance.getUsers().map(u => ({
    id: u.id,
    name: u.name,
    email: u.email,
    role: u.role,
    createdAt: u.createdAt
  }));
  res.json(publicUsers);
});

// Change user role
app.put('/api/users/:id/role', authenticateToken, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const roleSchema = z.object({
    role: z.enum(['customer', 'manager', 'admin'])
  });

  const result = roleSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ errors: result.error.issues });
    return;
  }

  // Prevent admin from revoking their own super-admin privileges accidentally
  if (req.params.id === req.user!.id && result.data.role !== 'admin') {
    res.status(400).json({ message: "Self-revocation is disabled. You cannot demote yourself from Admin." });
    return;
  }

  const success = dbInstance.updateUserRole(req.params.id, result.data.role);
  if (!success) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  res.json({ message: "User role updated successfully." });
});

// Delete user / revoke access
app.delete('/api/users/:id', authenticateToken, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  if (req.params.id === req.user!.id) {
    res.status(400).json({ message: "Suicide prevention: You cannot delete your own admin account." });
    return;
  }

  const success = dbInstance.deleteUser(req.params.id);
  if (!success) {
    res.status(404).json({ message: "User not found." });
    return;
  }
  res.json({ message: "User account deleted and access revoked successfully." });
});

// Create Staff User (Admin Only)
app.post('/api/users/staff', authenticateToken, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const staffCreateSchema = z.object({
    name: z.string().min(2),
    email: z.string().email(),
    password: z.string().min(6),
    role: z.enum(['manager', 'admin'])
  });

  const result = staffCreateSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ errors: result.error.issues });
    return;
  }

  const { name, email, password, role } = result.data;

  const existing = dbInstance.getUserByEmail(email);
  if (existing) {
    res.status(400).json({ message: "User with this email already exists." });
    return;
  }

  const salt = generateSalt();
  const passwordHash = hashPassword(password, salt);

  const newUser = dbInstance.createUser({
    name,
    email,
    passwordHash,
    salt,
    role
  });

  res.status(201).json({
    id: newUser.id,
    name: newUser.name,
    email: newUser.email,
    role: newUser.role,
    createdAt: newUser.createdAt
  });
});

// 5. SYSTEM SETTINGS (GET: public, PUT: Admin only)
app.get('/api/settings', (req: Request, res: Response) => {
  res.json(dbInstance.getSettings());
});

app.put('/api/settings', authenticateToken, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const settingsSchema = z.object({
    taxRate: z.number().nonnegative(),
    promotionalBanner: z.string(),
    storeName: z.string().min(1),
    storeEmail: z.string().email(),
    discountCodes: z.array(z.object({
      code: z.string().min(1),
      discountPercent: z.number().min(0).max(100),
      active: z.boolean()
    }))
  });

  const result = settingsSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ errors: result.error.issues });
    return;
  }

  const updatedSettings = dbInstance.updateSettings(result.data);
  res.json(updatedSettings);
});

// 6. FINANCIAL ANALYTICS DASHBOARD (Admin Only)
app.get('/api/analytics', authenticateToken, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const orders = dbInstance.getOrders();
  const products = dbInstance.getProducts();

  // Filter only 'Paid' orders or all default orders (which are confirmed Paid in RUPAT shop)
  const paidOrders = orders.filter(o => o.paymentStatus === 'Paid');

  // Total Revenue
  const totalRevenue = Number(paidOrders.reduce((sum, o) => sum + o.totalAmount, 0).toFixed(2));

  // Average Order Value (AOV)
  const averageOrderValue = paidOrders.length > 0 
    ? Number((totalRevenue / paidOrders.length).toFixed(2)) 
    : 0;

  // Best-selling cosmetics computation
  const itemSalesMap: Record<string, { name: string; quantity: number; revenue: number }> = {};
  paidOrders.forEach(order => {
    order.items.forEach(item => {
      if (!itemSalesMap[item.productId]) {
        itemSalesMap[item.productId] = { name: item.name, quantity: 0, revenue: 0 };
      }
      itemSalesMap[item.productId].quantity += item.quantity;
      itemSalesMap[item.productId].revenue += (item.price * item.quantity);
    });
  });

  const bestSellers = Object.entries(itemSalesMap)
    .map(([id, stats]) => ({ id, ...stats }))
    .sort((a, b) => b.quantity - a.quantity)
    .slice(0, 5);

  // Monthly Sales computation for 2026
  const monthlySalesMap: Record<string, number> = {
    "Jan": 0, "Feb": 0, "Mar": 0, "Apr": 0, "May": 0, "Jun": 0, "Jul": 0, "Aug": 0, "Sep": 0, "Oct": 0, "Nov": 0, "Dec": 0
  };

  paidOrders.forEach(order => {
    const date = new Date(order.createdAt);
    const month = date.toLocaleString('default', { month: 'short' });
    if (monthlySalesMap[month] !== undefined) {
      monthlySalesMap[month] += order.totalAmount;
    }
  });

  const monthlySales = Object.entries(monthlySalesMap).map(([month, amount]) => ({
    month,
    revenue: Number(amount.toFixed(2))
  }));

  // Low stock alert count
  const lowStockCount = products.filter(p => p.stockCount < 10).length;

  res.json({
    totalRevenue,
    averageOrderValue,
    totalOrdersCount: paidOrders.length,
    lowStockCount,
    bestSellers,
    monthlySales
  });
});

// 7. GEMINI AI SKINCARE & BEAUTY ADVISOR (Lazy-loaded client for maximum safety)
let aiClient: GoogleGenAI | null = null;

function getAIClient(): GoogleGenAI | null {
  if (!aiClient) {
    const key = process.env.GEMINI_API_KEY;
    if (key && key !== "MY_GEMINI_API_KEY") {
      aiClient = new GoogleGenAI({ apiKey: key });
    }
  }
  return aiClient;
}

app.post('/api/chatbot', async (req: Request, res: Response) => {
  const chatSchema = z.object({
    message: z.string().min(1, { message: "Message is required" }),
    history: z.array(z.object({
      role: z.enum(['user', 'model']),
      text: z.string()
    })).optional()
  });

  const result = chatSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ errors: result.error.issues });
    return;
  }

  const { message, history = [] } = result.data;
  const products = dbInstance.getProducts();

  // Try using actual server-side Gemini
  const client = getAIClient();
  if (client) {
    try {
      // Build a comprehensive system prompt presenting RUPAT's premium catalog
      const productCatalogText = products.map(p => 
        `- ${p.name} (SKU: ${p.sku}): $${p.price}. For skin: ${p.skinType}. Categories: ${p.categories.join(', ')}. Details: ${p.description}`
      ).join('\n');

      const systemInstruction = `You are the premium digital beauty concierge and skin concierge for the luxury cosmetics brand RUPAT.
Your style is elegant, highly professional, warm, helpful, and sophisticated.
You are extremely knowledgeable about ingredients and skin types.
Recommend specific RUPAT products from the catalog provided below when answering user skin questions (e.g. oily skin, fine lines, lipstick shades).

Here is RUPAT's Premium Catalog:
${productCatalogText}

Provide tailored consultations, skin tips, or makeup guidance. Keep answers concise, beautiful, and directly relevant. Focus strictly on human skin and cosmetics advice. If the customer asks questions unrelated to beauty, skin, or cosmetics, elegantly direct them back to skincare and luxury makeup.`;

      const contents = [
        { role: "user", parts: [{ text: systemInstruction }] },
        ...history.map(h => ({
          role: h.role,
          parts: [{ text: h.text }]
        })),
        { role: "user", parts: [{ text: message }] }
      ];

      const response = await client.models.generateContent({
        model: "gemini-2.5-flash",
        contents: contents as any
      });

      res.json({ reply: response.text });
      return;
    } catch (e) {
      console.error("Gemini API call failed, falling back to rule-based advisor:", e);
    }
  }

  // Graceful rule-based fallback advisor if Gemini key is missing or calls fail
  const userQueryLower = message.toLowerCase();
  let reply = "I would be absolutely delighted to assist you with your RUPAT cosmetics ritual. ";

  if (userQueryLower.includes("dry") || userQueryLower.includes("hydrate") || userQueryLower.includes("moisturizer")) {
    const plumper = products.find(p => p.id === "p6");
    const toner = products.find(p => p.id === "p5");
    reply += `To cocoon dry skin in lush hydration, I highly recommend our **${plumper?.name || "Whipped Hyaluronic Plumping Moisturizer"}** ($${plumper?.price || 58.00}) which seals in moisture for 48 hours. Complement this with our soothing, organic **${toner?.name || "Pure Bulgarian Rose Dew Toner"}** ($${toner?.price || 28.00}) immediately after cleansing to balance pH and lock in pristine skin hydration.`;
  } else if (userQueryLower.includes("oily") || userQueryLower.includes("cleanser") || userQueryLower.includes("pores")) {
    const cleanser = products.find(p => p.id === "p7");
    const foundation = products.find(p => p.id === "p1");
    reply += `For managing excess oil, pristine cleansing is paramount. Our **${cleanser?.name || "Herbal Green Tea Cleansing Oil"}** ($${cleanser?.price || 36.00}) gently dissolves oil and makeup residues with green tea antioxidants. For a flawless velvet makeup base, try the weightless **${foundation?.name || "Luminous Silk Liquid Foundation"}** ($${foundation?.price || 64.00}) which offers beautifully balanced satin coverage.`;
  } else if (userQueryLower.includes("lipstick") || userQueryLower.includes("lip") || userQueryLower.includes("red") || userQueryLower.includes("color")) {
    const lip = products.find(p => p.id === "p2");
    reply += `To indulge your lips, our award-winning **${lip?.name || "Hydrating Velvet Matte Lipstick"}** ($${lip?.price || 32.00}) is a masterpiece. It provides rich, velvety full-pigment coverage with organic Shea Butter and Jojoba Oil to keep lips moisturized without feathering.`;
  } else if (userQueryLower.includes("serum") || userQueryLower.includes("repair") || userQueryLower.includes("wrinkle") || userQueryLower.includes("night") || userQueryLower.includes("aging")) {
    const serum = products.find(p => p.id === "p3");
    reply += `For deep overnight rejuvenation, our **${serum?.name || "Advanced Night Repair Botantical Serum"}** ($${serum?.price || 88.00}) is unrivaled. Packed with Hyaluronic Acid and Centella Asiatica, it works in tandem with your skin's nocturnal recovery cycle to visibly refine texture, plump lines, and restore radiant dewiness.`;
  } else if (userQueryLower.includes("vegan") || userQueryLower.includes("cruelty") || userQueryLower.includes("animal")) {
    const veganProducts = products.filter(p => p.preferences.includes("Vegan") || p.preferences.includes("Cruelty-Free"));
    reply += `At RUPAT, we believe in luxury without compromise. The majority of our collection is completely **Vegan and Cruelty-Free**. Beautiful highlights include our **${veganProducts[0]?.name}**, **${veganProducts[1]?.name}**, and the **${veganProducts[2]?.name}**. Our formulations are strictly organic and never tested on animals.`;
  } else {
    reply += "Could you please share your specific skin type (Oily, Dry, Sensitive, or Combination) or the makeup product category you are looking to explore? I am here to design the ultimate bespoke beauty ritual for you.";
  }

  res.json({ reply });
});

// ============================================================================
// VITE OR STATIC FILE SERVING FOR FULL-STACK CONTEXT
// ============================================================================

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[RUPAT Cosmetics Server] Running on http://localhost:${PORT} [ENV: ${process.env.NODE_ENV || 'development'}]`);
  });
}

startServer();
