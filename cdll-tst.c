#include "cdll.h"
#include "stdio.h"
#include "stdlib.h"

typedef struct CdllTestRec_ {
	CdllNodeRec cdll;
	char    *txt;
} CdllTestRec, *CdllTest;

static CdllNode cdllTestAlloc(char *txt)
{
CdllTest rval = malloc(sizeof(*rval));
	cdll_init_el((CdllNode)rval);
	rval->txt = txt;
	return (CdllNode)rval;
}


CdllNodeRec anchor = { &anchor, &anchor };

static CdllNode pprev(CdllNode s, CdllNode p)
{
	return (s==p) ? p : pprev(s,p->p);
}

static void
cdllTestDump(CdllNode a)
{
CdllNode p;
printf("Dumping: forward                       reverse\n");
for (p = a->n; p!=a; p=p->n) {
printf("         %-30s"                        "%s\n",
	((CdllTest)p)->txt, ((CdllTest)pprev(p,p->p))->txt);
}
}

int
main()
{
CdllNode a;

		a = cdllTestAlloc("head 1");
		cdll_splerge_head(&anchor,a);
		a = cdllTestAlloc("tail 1");
		cdll_splerge_tail(&anchor,a);
		a = cdllTestAlloc("tail 2");
		cdll_splerge_tail(&anchor,a);
		a = cdllTestAlloc("head 2");
		cdll_splerge_head(&anchor,a);
		a = cdllTestAlloc("head 3");
		cdll_splerge_head(&anchor,a);
	cdllTestDump(&anchor);

	printf("removing tail 1");
	a = anchor.p->p;
	cdll_remove_el(a);
	printf("A dump of 'tail 1'\n");
	cdllTestDump(a);
	printf("A dump of the rest\n");
	cdllTestDump(&anchor);
	printf("Now cleaning up\n");
	
	while ( (a=cdll_dequeue_head(&anchor)) != &anchor ) {
		printf("dequeued '%s'\n",((CdllTest)a)->txt);
		cdllTestDump(a);
		a->p = a->n = 0;
		cdllTestDump(&anchor);
		free(a);
	}
	cdllTestDump(&anchor);
}
