"""Presentation-only table controls and escaped search highlights."""
import re
from markupsafe import Markup, escape
DATE_KEYS={'at','seen','last_seen','first_seen','created','expires','new_seen','block_recorded','block_expires'}

def highlight(value, table, key, query=''):
 text=str(value or '')
 selected=table['state'].get(table['prefix']+'f_'+key,'')
 terms=[query]
 if key not in table['choices'] and key not in table['dates'] and isinstance(selected,str):terms.append(selected)
 if key=='asn' and isinstance(selected,str):terms.append(selected)
 terms=sorted({t.strip() for t in terms if isinstance(t,str) and t.strip()},key=len,reverse=True)
 if not terms:return escape(text)
 pattern=re.compile('|'.join(re.escape(t) for t in terms),re.IGNORECASE)
 parts=[];last=0
 for match in pattern.finditer(text):
  parts.extend([escape(text[last:match.start()]),Markup('<mark class="filter-match">'),escape(match.group()),Markup('</mark>')]);last=match.end()
 parts.append(escape(text[last:]))
 return Markup('').join(parts)
