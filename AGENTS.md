SafeOps UI Engineering & Design Rules

Core Principle

Build interfaces that feel intentionally designed by a strong product designer, not generated from a generic UI template.

Before creating a new UI, understand:

* the product context
* the user’s task
* the existing design language
* the information hierarchy
* the visual relationships between elements

Do not introduce visual decoration merely to make a screen look “premium.”

⸻

1. Before Writing UI Code

For any meaningful UI task:

1. Inspect the existing project and nearby components.
2. Reuse existing components, tokens, typography and patterns where appropriate.
3. Identify the information hierarchy.
4. If the design direction is unclear, use the Inspo MCP for visual research.
5. Study real production interfaces rather than relying on generic AI conventions.
6. Decide the visual direction before implementation.
7. Only then write the UI code.

Do not redesign unrelated parts of the application.

Do not replace existing UI simply because a different implementation looks more impressive.

⸻

2. Inspo MCP

Use the Inspo MCP as a design research tool.

Do not blindly copy references.

Preferred workflow

Start with:

recommend

when the visual direction is not yet established.

Then use:

search_screens

to investigate real production references.

Use:

get_design_system

to inspect:

* typography
* type scale
* colour roles
* spacing
* radius
* CSS variables
* visual hierarchy

Use:

compare

when several references look promising and a coherent visual direction needs to be established.

Use:

find_components

when researching a specific UI pattern.

Use:

get_site_pages

when understanding how a strong product structures an entire experience rather than a single screen.

Research rule

Use multiple references when appropriate.

Triangulate patterns instead of copying one website.

The goal is to extract principles, not reproduce a website.

Never copy:

* branding
* logos
* proprietary illustrations
* exact copy
* distinctive assets
* exact layouts without meaningful adaptation

⸻

3. Anti-AI-Slop Rules

Avoid generic UI patterns unless the product genuinely requires them.

Do NOT automatically use:

* excessive rounded cards
* excessive pill buttons
* giant gradients
* glassmorphism everywhere
* floating blobs
* arbitrary glowing effects
* excessive shadows
* random decorative circles
* gradient text
* oversized headings without hierarchy
* cards inside cards inside cards
* excessive badges
* meaningless statistics
* fake testimonials
* unnecessary icons
* excessive animations
* “AI-looking” purple/blue gradient palettes
* identical hero → cards → testimonials layouts
* generic dashboard grids
* unnecessary empty space
* visual decoration without product purpose

A UI is not premium merely because it contains:

* gradients
* blur
* shadows
* rounded corners
* animations
* large typography

Use these only when they support the product’s visual language.

⸻

4. Visual Hierarchy

Every screen must have a clear hierarchy.

Determine:

1. Primary action
2. Primary information
3. Secondary information
4. Supporting information
5. Optional information

The most important element should not compete visually with secondary elements.

Use scale, spacing, position, typography and contrast to communicate hierarchy.

Do not make every element visually loud.

⸻

5. Layout

Prefer intentional composition over collections of cards.

Use:

* meaningful grouping
* strong alignment
* deliberate whitespace
* asymmetric layouts when appropriate
* clear content density
* consistent containers
* predictable spacing rhythm

Do not force everything into equal-width cards.

Do not use a grid simply because a grid is easy to generate.

Ask:

What is the natural relationship between these pieces of information?

Then choose the layout that communicates that relationship.

⸻

6. Typography

Typography is a major part of the interface.

Use a deliberate type hierarchy.

Define clear roles for:

* display
* heading
* section heading
* body
* metadata
* labels
* supporting text

Avoid using many unrelated font sizes.

Do not compensate for weak hierarchy with oversized text.

Prefer readable line lengths and intentional text density.

⸻

7. Colour

Use colour intentionally.

Start with a small semantic palette.

Typical roles:

* background
* elevated surface
* primary text
* secondary text
* border
* primary action
* accent
* success
* warning
* error

Do not introduce a new colour for every component.

Accent colour should communicate hierarchy or interaction rather than decorate the entire interface.

Avoid excessive gradients unless they are explicitly part of the established design language.

⸻

8. Components

Prefer composition of reusable components.

Before creating a new component:

1. Search the existing codebase.
2. Determine whether an existing component can be reused.
3. Extend an existing component when appropriate.
4. Create a new component only when there is a meaningful abstraction.

Do not create duplicate components with slightly different names.

Do not over-abstract simple UI.

Components should have clear responsibilities.

⸻

9. Animation

Use the Animate UI skill when appropriate.

Animation should communicate:

* state changes
* hierarchy
* continuity
* interaction feedback
* navigation
* spatial relationships

Animation should NOT exist merely because it is technically possible.

Prefer:

* subtle entrance transitions
* meaningful hover/focus states
* smooth state transitions
* contextual movement
* restrained micro-interactions

Avoid:

* constant bouncing
* unnecessary spinning
* excessive spring effects
* animations on every element
* distracting parallax
* long transitions
* decorative motion

Animation should support the user’s understanding of the interface.

Respect reduced-motion preferences.

⸻

10. Interaction Design

Every interactive element should provide appropriate feedback.

States should be considered explicitly:

* default
* hover
* focus
* active
* disabled
* loading
* success
* error
* empty
* selected

Do not design only the “happy path.”

Loading and empty states should feel like intentional parts of the product rather than placeholders.

⸻

11. Responsive Design

Do not simply shrink desktop layouts.

Determine how hierarchy changes across screen sizes.

Consider:

* navigation changes
* content prioritisation
* stacking
* touch targets
* typography scaling
* spacing changes
* image cropping
* interaction changes

Mobile should feel intentionally designed.

⸻

12. Accessibility

Accessibility is part of the design.

Ensure:

* sufficient contrast
* visible focus states
* keyboard accessibility where applicable
* appropriate semantic elements
* meaningful labels
* reasonable touch targets
* reduced-motion support
* readable typography

Do not sacrifice usability for visual novelty.

⸻

13. Implementation Discipline

When implementing a UI task:

First

Inspect.

Second

Research if needed.

Third

Plan the hierarchy.

Fourth

Implement.

Fifth

Review visually.

Sixth

Refine.

Do not immediately start rewriting large portions of the application.

Prefer the smallest coherent change that produces the intended result.

⸻

14. Existing Design System Has Priority

If the project already has an established design system:

Existing project conventions > generic UI conventions > personal preference.

Preserve existing:

* tokens
* typography
* spacing
* component APIs
* navigation patterns
* interaction patterns
* accessibility conventions

Do not introduce a competing design system without explicit instruction.

⸻

15. No Unnecessary Dependencies

Do not install a new UI library merely to implement a simple component.

Before adding a dependency:

1. Check whether the project already provides the functionality.
2. Check whether an existing dependency can solve it.
3. Consider whether the dependency is justified by long-term maintenance.

Do not add dependencies silently.

Explain meaningful dependency additions.

⸻

16. Design Review Before Finalising

Before considering a UI task complete, inspect the result critically.

Ask:

Visual

* Does this look intentionally designed?
* Is there a clear visual hierarchy?
* Is anything unnecessarily decorative?
* Are there too many cards?
* Are there too many rounded elements?
* Is the colour palette coherent?
* Does the typography feel deliberate?

UX

* Is the primary action obvious?
* Is the information easy to scan?
* Are loading, empty and error states handled?
* Does interaction feedback make sense?

Engineering

* Are existing components reused?
* Are abstractions reasonable?
* Did we introduce unnecessary dependencies?
* Is responsive behaviour handled?
* Is accessibility considered?

If the answer is no, refine before finishing.

⸻

17. Do Not Claim Design Quality

Do not describe the UI as:

* “premium”
* “modern”
* “beautiful”
* “sleek”
* “world-class”
* “cutting-edge”

unless the implementation actually demonstrates those qualities.

Show quality through the interface rather than through adjectives.

⸻

18. When the User Says “Make It Better”

Do not randomly add visual effects.

Instead:

1. Identify what is weak.
2. Determine whether the problem is hierarchy, spacing, typography, composition, interaction or content.
3. Research relevant references with Inspo MCP if useful.
4. Make targeted improvements.
5. Preserve what already works.

⸻

19. When the User Requests a New Screen

Before implementation, determine:

Purpose
↓
Primary user action
↓
Information hierarchy
↓
Layout
↓
Typography
↓
Colour
↓
Interaction
↓
Animation

Do not start with:

Card
Card
Card
Button
Gradient
Shadow

⸻

20. Final Rule

The objective is not to make every screen visually unusual.

The objective is to make every design decision intentional.

Use restraint.

Use hierarchy.

Use real references.

Use animation purposefully.

Reuse existing patterns.

Make the interface feel like one coherent product.
