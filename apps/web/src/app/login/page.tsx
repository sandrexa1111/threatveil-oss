import { Login } from '@/components/login';
export const dynamic = 'force-dynamic';
export default function Page(){ return <Login localEnabled={process.env.TV_LOCAL_AUTH==='true' && process.env.TV_ENV!=='production'}/>; }
