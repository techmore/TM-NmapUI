# GitHub Issue: Feature Request - Resume asset display from previous scan with date indication

## Title: Feature: Resume asset display from previous scan with date indication

## Summary:
- When a network is identified, resume asset display from the last scan instead of starting fresh
- Add visual indication when displayed assets are from a previous day's scan  
- Improve user experience by showing recent historical data when no new scan is run

## Problem Statement:
Currently, when a network is identified (either automatically or manually), the asset display starts fresh without showing any previous scan results. This means users lose context from recent scans and must run a new scan every time to see asset information, even if they just scanned the same network recently.

## Proposed Solution:

### 1. Resume from Last Scan
- When network identification occurs (automatic or manual), check for the most recent scan for that customer/network
- If a recent scan exists (within configurable timeframe, e.g., 7 days), display those assets by default
- Show a clear indication that the data is from a previous scan
- Allow users to either run a new scan or continue viewing the historical data

### 2. Date/Time Indication
- Add visual indicators when displayed assets are from a previous day:
  - Badge/timestamp showing "Scanned on [date]"
  - Color coding (e.g., olive/yellow tint for older data)
  - Time since last scan ("2 days ago", "Yesterday", etc.)
- Distinguish between:
  - Today's scans (normal display)
  - Yesterday's scans (subtle indication)
  - Older scans (more prominent indication)

### 3. User Controls
- Add "Run New Scan" button when showing historical data
- Add "View Scan History" option to see other recent scans
- Configurable preference for how old data should be auto-resumed

## Implementation Details:

### Backend Changes (app.py)
1. **Enhanced Customer Identification Event**
   - Modify `customer_identified` event to include last scan metadata
   - Add function to get most recent scan for customer:
   ```python
   def get_most_recent_scan(customer_id, max_days=7):
       """Get the most recent scan for a customer within specified days"""
   ```

2. **New Socket Events**
   - `last_scan_available` - Send last scan data when available
   - `resume_from_last_scan` - Client requests to resume from last scan
   - `scan_metadata` - Send scan metadata with timestamps

3. **Scan Metadata Enhancement**
   - Ensure all scans have complete timestamp data
   - Add scan duration and completion time to metadata
   - Track scan quality/completeness metrics

### Frontend Changes (templates/index.html)
1. **Visual Indicators**
   - Add timestamp badge to asset display area
   - Color coding for scan age:
     - Today: Default styling
     - Yesterday: Light olive tint
     - 2+ days: More prominent yellow/amber tint
   - "Last scanned: [time]" indicator

2. **UI Components**
   - Add "Resume from Last Scan" modal/confirmation
   - "Run New Scan" button when showing historical data
   - Scan age indicator in header
   - Tooltip showing exact scan time

3. **JavaScript Functions**
   - `handleResumeFromLastScan()` - Load and display historical assets
   - `updateScanAgeIndicator()` - Update visual indicators based on scan age
   - `showHistoricalDataWarning()` - Show when data is from previous day

### Data Structure Changes
1. **Enhanced Metadata**
   ```json
   {
     "timestamp": "2026-01-09T10:30:00",
     "scan_duration": "00:05:23", 
     "total_hosts": 15,
     "hosts_up": 12,
     "scan_complete": true,
     "scan_quality": "high"
   }
   ```

2. **Customer Assignment Enhancement**
   - Track last scan timestamp per customer
   - Cache recent scan results for quick resume

## User Experience Flow:

### Scenario 1: Same Day Scan
1. User identifies network (auto or manual)
2. System shows today's scan results (if available)
3. Normal display, no special indication needed

### Scenario 2: Previous Day Scan
1. User identifies network
2. System detects last scan was yesterday
3. Shows assets with subtle "Yesterday" indicator
4. Offers "Run New Scan" option

### Scenario 3: Older Scan
1. User identifies network
2. System detects last scan was 2+ days ago
3. Shows assets with prominent "Scanned on [date]" indicator
4. Strong recommendation to run new scan
5. Color tint to indicate aged data

## Configuration Options:
- Maximum age for auto-resume (default: 7 days)
- Color scheme for scan age indication
- Whether to auto-resume or prompt user
- Scan quality thresholds for resume eligibility

## Benefits:
1. **Improved Efficiency**: No need to re-scan recently scanned networks
2. **Better Context**: Users see recent historical data immediately
3. **Reduced Network Load**: Fewer unnecessary scans
4. **Enhanced UX**: Faster access to asset information
5. **Data Continuity**: Maintains context between sessions

## Acceptance Criteria:
1. ✅ Network identification checks for recent scans
2. ✅ Historical assets displayed with appropriate visual indicators
3. ✅ Clear distinction between today's and previous day's data
4. ✅ User can choose to run new scan or use historical data
5. ✅ Configuration options for resume behavior
6. ✅ Graceful fallback when no historical data exists
7. ✅ Performance optimization for quick data loading
8. ✅ Accessibility compliance for visual indicators

## Technical Notes:
- Leverage existing scan history infrastructure
- Use existing metadata.json files for scan information
- Integrate with current customer identification system
- Maintain backward compatibility with existing scan data

---

## How to Create This Issue:

1. Go to your GitHub repository: https://github.com/techmore/TM-NmapUI
2. Click on "Issues" tab
3. Click "New issue" button
4. Copy and paste the content above (from "Title:" to the end)
5. Add appropriate labels (e.g., "enhancement", "feature-request", "ui/ux")
6. Click "Submit new issue"

## Alternative: Install GitHub CLI

If you want to create issues directly from the command line in the future:

```bash
# On macOS with Homebrew
brew install gh

# Then authenticate
gh auth login

# Create issue directly
gh issue create --title "Feature: Resume asset display from previous scan with date indication" --body "$(cat docs/issues/GITHUB_ISSUE_CONTENT.md)"
```