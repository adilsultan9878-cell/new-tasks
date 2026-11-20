import { Compass } from 'lucide-react'
import { Link } from 'react-router-dom'

import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'

export function NotFoundPage({ embedded = false }: { embedded?: boolean }) {
  return (
    <div className={embedded ? 'py-16' : 'flex min-h-screen items-center justify-center p-6'}>
      <EmptyState icon={Compass} title="Page not found" action={<Link to="/"><Button variant="primary">Go to console</Button></Link>}>
        The page you requested does not exist.
      </EmptyState>
    </div>
  )
}
