export type BillQueryParams = Record<string, string | number | boolean>

export interface AccountBillQueryResult {
  available: boolean
  items: any[]
}

export interface AccountBillQueryOptions {
  pageSize?: number
  maxPages?: number
  timeoutMs?: number
}

export function isBillQueryAvailable(response: any): boolean {
  return response !== null
    && typeof response === "object"
    && response.Success !== false
    && (response.Code === undefined || response.Code === "Success")
    && Array.isArray(response.Data?.Items?.Item)
}

function pageInteger(value: unknown): number | undefined {
  if (typeof value !== "number" && typeof value !== "string") return undefined
  if (typeof value === "string" && !/^\d+$/.test(value.trim())) return undefined
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : undefined
}

function stableRecord(value: any): any {
  if (Array.isArray(value)) return value.map(stableRecord)
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map(key => [key, stableRecord(value[key])])
    )
  }
  return value
}

export async function queryAccountBillPages(
  request: (params: BillQueryParams) => Promise<any>,
  params: BillQueryParams,
  options: AccountBillQueryOptions = {}
): Promise<AccountBillQueryResult> {
  const unavailable = (): AccountBillQueryResult => ({ available: false, items: [] })
  const pageSize = options.pageSize ?? pageInteger(params.PageSize) ?? 300
  const maxPages = options.maxPages ?? 100
  const timeoutMs = options.timeoutMs ?? 12000
  if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 300
    || !Number.isSafeInteger(maxPages) || maxPages < 1 || maxPages > 100
    || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return unavailable()
  }

  let expired = false
  const deadline = Date.now() + timeoutMs
  const collect = async (): Promise<AccountBillQueryResult> => {
    const items: any[] = []
    const seenPages = new Set<string>()
    let totalCount: number | undefined
    for (let pageNum = 1; pageNum <= maxPages; pageNum++) {
      if (expired || Date.now() >= deadline) return unavailable()
      const response = await request({ ...params, PageSize: pageSize, PageNum: pageNum })
      if (expired || Date.now() >= deadline || !isBillQueryAvailable(response)) {
        return unavailable()
      }
      const pageItems = response.Data.Items.Item as any[]
      if (pageItems.length > pageSize) return unavailable()
      const rawPageNum = response.Data.PageNum
      if (rawPageNum !== undefined && pageInteger(rawPageNum) !== pageNum) {
        return unavailable()
      }
      const rawPageSize = response.Data.PageSize
      if (rawPageSize !== undefined && pageInteger(rawPageSize) !== pageSize) {
        return unavailable()
      }
      const rawTotal = response.Data.TotalCount !== undefined
        ? response.Data.TotalCount
        : response.TotalCount
      if (rawTotal !== undefined) {
        const reportedTotal = pageInteger(rawTotal)
        if (reportedTotal === undefined
          || reportedTotal > pageSize * maxPages
          || (totalCount !== undefined && totalCount !== reportedTotal)) {
          return unavailable()
        }
        totalCount = reportedTotal
      }
      if (pageItems.length > 0) {
        const fingerprint = JSON.stringify(pageItems.map(item => JSON.stringify(stableRecord(item))).sort())
        if (seenPages.has(fingerprint)) return unavailable()
        seenPages.add(fingerprint)
        items.push(...pageItems)
      }

      if (totalCount !== undefined) {
        if (items.length > totalCount) return unavailable()
        if (items.length === totalCount) return { available: true, items }
        if (pageItems.length === 0) return unavailable()
      } else if (pageItems.length < pageSize) {
        return { available: true, items }
      }
    }
    return unavailable()
  }

  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      collect().catch(unavailable),
      new Promise<AccountBillQueryResult>(resolve => {
        timer = setTimeout(() => {
          expired = true
          resolve(unavailable())
        }, timeoutMs)
      })
    ])
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}

export interface RecentBillingDate {
  dateStr: string
  displayDate: string
  isToday: boolean
  billingCycle: string
}

export function recentBillingDates(now: Date, count: number = 7): RecentBillingDate[] {
  if (!Number.isFinite(now.getTime()) || !Number.isSafeInteger(count) || count < 1) return []
  return Array.from({ length: count }, (_, index) => {
    const date = new Date(now.getFullYear(), now.getMonth(), now.getDate() - index)
    const year = String(date.getFullYear()).padStart(4, "0")
    const month = String(date.getMonth() + 1).padStart(2, "0")
    const day = String(date.getDate()).padStart(2, "0")
    return {
      dateStr: `${year}-${month}-${day}`,
      displayDate: `${month}-${day}`,
      isToday: index === 0,
      billingCycle: `${year}-${month}`
    }
  })
}
