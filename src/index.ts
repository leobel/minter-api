import express, { Request, Response , Application } from 'express';
import dotenv from 'dotenv';
import { mintToken } from './services/token-mint';
import { Seed } from './utils';
import cors from 'cors';
import { createScript } from './services/create-script';
import { signTx } from './services/crypto';
import { updateToken } from './services/token-update';
import { burnToken } from './services/token-burn';

//For env File 
dotenv.config();

const app: Application = express();
const port = process.env.PORT || 8000;

app.use(express.json());
app.use(cors())

app.get('/', (req: Request, res: Response) => {
  res.send('Welcome to Minter Server!!!');
});

app.post('/mintToken', async (req: Request, res: Response) => {
  const build = await mintToken(req.body);
  res.json(build);
});

app.post('/burnToken', async (req: Request, res: Response) => {
  const build = await burnToken(req.body);
  res.json(build);
});

app.post('/updateToken', async (req: Request, res: Response) => {
  const build = await updateToken(req.body);
  res.json(build);
});

app.post('/signTx', (req: Request, res: Response) => {
  const tx = signTx(req.body);
  res.json({ tx });
});

app.post('/createScript', async (req: Request, res: Response) => {
  const script = await createScript(req.body);
  res.json(script);

})

app.listen(port, () => {
  console.log(`Server is Fire at http://localhost:${port}`);
});