+++
title = "Magma labelled graphs are homomorphisms from a specific partial semigroup!"
date = 2026-09-24

[extra]
latex = true
+++

last week i was reading [this paper](https://doi.org/10.1145/3729298) by lesbre, lemerre, et al and it mentioned (section 3.1) this notion of a graph with paths labelled by a magma coherent with the operation.
they fix a set $\mathbb{L}$ and ask for a binary operation $; : \mathbb{L} \times \mathbb{L} \to \mathbb{L}$ thought of as composition.
then for some directed graph with loops $(\mathbb{V}, \mathbb{E} \subseteq \mathbb{V} \times \mathbb{V})$, they ask for a function $L : \mathbb{E}^* \to \mathbb{L}$ from the transitive closure of edges, such that composite paths respect the binary operation!
specifically, if we have some paths $l_1 : a \leadsto b$ and $l_2 : b \leadsto c$ then the composite path should be labelled $l_1; l_2 : a \leadsto c$.
this sure feels like a homomorphism property doesn't it...

## partial magmas, semigroups and monoids
sorry haters there is going to be some category theory here.

there is a category with objects being sets and morphisms being partial functions!
to see this, recall that a partial function $f : A \rightharpoondown B$ is equivalently a function $\hat{f} : A \to M B$ where $M$ is the maybe monad ($X \mapsto X \sqcup 1$).
if $\hat{f}$ maps to the added empty term at some element, then $f$ isn't defined there.
hence, the category of partial functions is the kleisli category of the maybe monad!
although this category does not have the same limits as the base category, the cartesian product does exist as the left adjoint is identity on objects.
moreover it defines a bifunctor on partial functions (a pair is defined from $A \times B$ iff it is on both $A$ and $B$).
since the left adjoint is a functor, it preserves isomorphisms and commuting diagrams.
hence the cartesian monoidal structure on sets defines a valid monoidal structure on partial functions!
this means that we can talk about magmas, semigroups and monoids in it!
as an aside, the category of partial functions is equivalent to the category of pointed sets (exercise!), and in this equivalence cartesian products correspond to smash products.

a magma in a monoidal category is simply an object $M$ equipped with a morphism $m : M \otimes M \to M$.
it becomes a semigroup if we impose associativity, which says that the two ways to multiply $m (1 \otimes m), m (m \otimes 1) : M \otimes M \otimes M \to M$ are equal!
(usually you'd draw a commutative diagram but i don't want to set that up with this js latex renderer...)
it then becomes a monoid if we require an additional morphsim $e : 1 \to M$ such that it is an identity, which means $m (1 \otimes e) = l$ and $m (e \otimes 1) = r$ (where $l, r$ are the left and right unitors of the monoidal category).

specialised to partial functions and unwrapping definitions, a semigroup is a set $S$ with a partial multiplication $\odot : S \times S \to S$ such that $(a \odot b) \odot c$ is defined iff $a \odot (b \odot c)$ is, and if so they are equal.
a monoid will be a set $M$ such that, if it is nonempty, it has an identity element $e$ such that $e \odot m = m \odot e = m$ for all $m \in M$.
i think it's pretty funny how there's this nonempty requirement and that the empty set has partial monoid structure

## the path partial semigroup
okay so now to the point of this post!
if $V$ is a set of vertices, then we can put partial semigroup structure on the set $V \times V$, the set of all possible path endpoints in a hypothetical graph!
the partial multiplication will be the composite of paths if the endpoints line up.
that is, $(a, b) \odot (b, c) = (a, c)$ and $(a, b) \odot (c, d)$ is not defined if $b \neq c$.
this is clearly partially associative!
i think that that this exists is pretty neat, but of course the point of this post was to talk about homomorphisms.
so, what is a homomorphism from this semigroup?

well... a partial magma homomorphism would require that if $a \odot b$ exists, then $f(a \odot b) = f(a) \odot f(b)$...
so if we have some assignment of value to the path $a \leadsto b$ and an assignment of value to $b \leadsto c$, we require that $f(a \leadsto c) = f(a \leadsto b) \odot f(b \leadsto c)$...
wow that's just the property from the start, yay!
indeed, a labelling as defined initially is a standard magma, but that would make it a perfectly valid partial magma.
so, a magma path labelled graph is a vertex set with a partial magma homomorphism from this path semigroup!
pretty cool i think!
the paper probably didn't need to make the composition operation total did it :3

## the path partial monoid

now... what if we are valued in a monoid instead of just a magma (like in the paper) and we want loops to map to identity elements?
a monoid homomorphism would have to preserve identities, so we would need to somehow make every self loop the identity element simultaneously as a monoid only has one identity.
although in the path semigroup, self loops act as identities when defined, in a partial monoid we require the identity to act as one to all elements... what to do?

well, we could identify all of the self loops in $V \times V$!
now we can work in some set $\mathcal{E} = V \times V / {\sim}$ with ${\sim} = \\{((v, v), (v', v')) | v, v' \in V\\}$ (an equivalence relation lol) and use the original semigroup structure (or maybe do a coequaliser idk) with the quotiented self loops acting as the identity.
it turns out that this indeed forms a partial monoid, hurray!
as we said before, this now means a partial monoid homomorphism from this monoid would be a labelling respecting the monoid structure while also sending loops to the identity!
how cool is that!
