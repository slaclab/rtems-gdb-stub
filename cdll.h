/*$Id$*/
/* Operate on circular doubly linked list */
#ifndef CIRC_DOUBLE_LINKED_LIST_H
#define CIRC_DOUBLE_LINKED_LIST_H

/* Circular doubly linked lists (CDLLs) are interesting:
 *  - the same operation 'splerge' can be used to
 *    a) merge two CDLLs
 *    b) split a CDLL into two CDLLs
 *  - no special cases when handling head / tail
 *    (in combination with an anchor element)
 *
 * Usage example: 
 *
 * Define a list anchor
 *  
 *      CdllNodeRec anchorNode = { &anchorNode, &anchorNode };
 *
 * Create an element and add at the head of the list
 *
 *      CdllNode el = malloc(sizeof(*el));
 *      cdll_init_el(el);
 *      cdll_splerge_head(&anchorNode,el);
 * 
 * Create an element and add at the tail
 *  
 *      CdllNode el = malloc(sizeof(*el));
 *      cdll_init_el(el);
 *      cdll_splerge_tail(&anchorNode,el);
 *
 * Forward traverse list extracting all elements
 *
 *      CdllNode ptr;
 *	    while ( (ptr=cdll_dequeue_head(&anchor)) != &anchor ) {
 *            work_on_(ptr);
 *            free(ptr);
 *      }
 *
 * Reverse traversing list (no extraction)
 *
 *      CdllNode ptr;
 *      for ( ptr = anchor.p; ptr!=&anchor; ptr=ptr->p ) {
 *            work_on(ptr);
 *      }
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CdllNodeRec_ *CdllNode;

typedef struct CdllNodeRec_ {
	CdllNode p,n;
} CdllNodeRec;

/* split/merge two lists 'at the head', i.e.
 *   merging makes a->n = 'old tail' of b
 *           and   b->n = 'old tail' of a
 *   splitting at a, b cuts the links at a->n, b->n
 */ 

static inline void
cdll_splerge_head(CdllNode a, CdllNode b)
{
register CdllNode tmp,tmp1;
/*
	a->n->p = b;
	b->n->p = a;
	tmp     = b->n;
	b->n    = a->n;
    a->n    = tmp;
*/
	tmp     = b->n;
	tmp1    = a->n;
    tmp1->p = b;
    tmp->p  = a;
    b->n    = tmp1;
    a->n    = tmp;
}

/* split/merge two lists 'at the tail', i.e.
 *   merging makes a->p = 'old head' of b
 *           and   b->p = 'old head' of a
 *   splitting at a, b cuts the links at a->p, b->p
 */ 
static inline void
cdll_splerge_tail(CdllNode a, CdllNode b)
{
register CdllNode tmp,tmp1;
/*
	a->p->n = b;
	b->p->n = a;
	tmp     = b->p;
	b->p    = a->p;
    a->p    = tmp;
*/
	tmp     = b->p;
	tmp1    = a->p;
    tmp1->n = b;
    tmp->n  = a;
    b->p    = tmp1;
    a->p    = tmp;
}

static inline CdllNode
cdll_dequeue_head(CdllNode a)
{
register CdllNode b = a->n;
	cdll_splerge_head(a,b);
	return b;
}

static inline CdllNode
cdll_remove_el(CdllNode b)
{
	cdll_splerge_head(b->p,b);
	return b;
}

static inline void cdll_init_el(CdllNode el)
{
	el->p = el->n = el;
}

#ifdef __cplusplus
}
#endif

#endif
